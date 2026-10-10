"""Actual MIME bytes and archive metadata, without mocked results or execution."""
from email.message import EmailMessage
from email import policy
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
from paw.core.parser_mail import parse_message_bytes, parse_eml_bytes, load_mail
from paw.core.mime_analysis import analyze_mime, MimeLimits, MimeLimitExceeded
from paw.core.attach import scan_attachments, archive_inventory
from paw.core.network_policy import offline_policy, violations
from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.scoring import score_case
from paw.core.rekor import verify_inclusion_proof


def message():
    result = EmailMessage(policy=policy.SMTP)
    result['From'] = 'Sender <sender@example.com>'
    result['To'] = 'recipient@example.net'
    result['Subject'] = 'MIME verification'
    result.set_content('Outer body')
    return result


def parse(value, limits=MimeLimits()):
    return analyze_mime(parse_message_bytes(value.as_bytes(), limits), limits)


class MimeContracts(unittest.TestCase):
    def test_declared_charset_preserves_accents_and_encoded_headers(self):
        raw = b'From: sender@example.com\r\nSubject: =?iso-8859-1?q?Pi=F9_caff=E8?=\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nPi\xf9 caff\xe8'
        result = analyze_mime(parse_message_bytes(raw))
        self.assertEqual(result['body_text'], 'Più caffè')
        self.assertEqual(str(parse_eml_bytes(raw)['subject']), 'Più caffè')
        self.assertEqual(result['metadata']['status'], 'completed')

    def test_unknown_charset_is_partial_without_silent_byte_dropping(self):
        raw = b'Content-Type: text/plain; charset=not-a-real-charset\r\n\r\na\xffb'
        result = analyze_mime(parse_message_bytes(raw))
        self.assertEqual(result['body_text'], 'a\ufffdb')
        self.assertEqual(result['metadata']['status'], 'partial')
        self.assertEqual(result['metadata']['parts'][0]['sha256'], hashlib.sha256(b'a\xffb').hexdigest())

    def test_html_only_preserves_href_entities_and_form_action(self):
        value = message()
        value.set_content('<a href="https://example.invalid/a?x=1&amp;y=2">Click</a><form action="https://example.invalid/post"></form>', subtype='html')
        result = parse(value)
        self.assertIn('https://example.invalid/a?x=1&y=2', result['urls'])
        self.assertIn('https://example.invalid/post', result['urls'])
        self.assertIn('Click', result['body_text'])

    def test_alternatives_are_retained_instead_of_last_html_only(self):
        value = message()
        value.add_alternative('<a href="https://example.invalid/one">First</a>', subtype='html')
        value.add_alternative('<a href="https://example.invalid/two">Second</a>', subtype='html')
        result = parse(value)
        self.assertIn('First', result['html'])
        self.assertIn('Second', result['html'])
        self.assertEqual(len(result['urls']), 2)

    def test_inline_binary_and_empty_attachments_are_not_lost(self):
        value = message()
        value.add_attachment(b'\x89PNG\r\n', maintype='image', subtype='png', disposition='inline')
        value.add_attachment(b'', maintype='application', subtype='octet-stream', filename='empty.bin')
        result = parse(value)
        attachments = scan_attachments(None, mime_result=result)
        self.assertEqual(len(attachments), 2)
        self.assertEqual(attachments[1]['sha256'], hashlib.sha256(b'').hexdigest())
        self.assertIsNone(attachments[0]['ole_macro'])
        self.assertEqual(attachments[0]['risk_level'], 'not_evaluated')

    def test_text_attachment_is_not_outer_body(self):
        value = message()
        value.add_attachment('Inner attachment https://example.invalid/attached', filename='letter.txt')
        result = parse(value)
        self.assertNotIn('Inner attachment', result['body_text'])
        self.assertEqual(result['urls'], [])
        self.assertEqual(len(result['attachments']), 1)

    def test_embedded_email_is_an_attachment_and_its_headers_do_not_leak(self):
        value, inner = message(), message()
        inner.replace_header('From', 'inner@attacker.invalid')
        inner.set_content('Inner body https://example.invalid/inner')
        value.add_attachment(inner, filename='forward.eml')
        result = parse(value)
        self.assertEqual(result['urls'], [])
        self.assertEqual(len(result['attachments']), 1)
        self.assertIn(b'inner@attacker.invalid', result['attachments'][0]['payload'])
        self.assertEqual(result['attachments'][0]['byte_source'], 'derived_embedded_message_serialization')

    def test_unhandled_calendar_is_preserved_as_not_evaluated(self):
        value = message()
        value.set_content('BEGIN:VCALENDAR\nURL:https://example.invalid/calendar\nEND:VCALENDAR', subtype='calendar')
        result = parse(value)
        self.assertEqual(result['metadata']['status'], 'partial')
        self.assertEqual(len(result['attachments']), 1)

    def test_malformed_base64_defect_is_persisted(self):
        raw = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj???'
        result = analyze_mime(parse_message_bytes(raw))
        self.assertEqual(result['metadata']['status'], 'partial')
        self.assertTrue(result['metadata']['issues'])

    def test_missing_multipart_boundary_does_not_pass_as_complete(self):
        raw = b'Content-Type: multipart/mixed\r\n\r\nUndelimited payload'
        result = analyze_mime(parse_message_bytes(raw))
        self.assertEqual(result['metadata']['status'], 'partial')
        self.assertTrue(result['metadata']['issues'])

    def test_count_limit_applies_during_parsing(self):
        value = message()
        for index in range(5): value.add_attachment(b'x', maintype='application', subtype='octet-stream', filename=f'{index}.bin')
        with self.assertRaises(MimeLimitExceeded): parse(value, MimeLimits(max_parts=3))

    def test_depth_and_decoded_byte_limits_are_explicit_failures(self):
        value = message()
        value.add_attachment(b'x'*100, maintype='application', subtype='octet-stream', filename='data.bin')
        with self.assertRaises(MimeLimitExceeded): parse(value, MimeLimits(max_depth=0))
        with self.assertRaises(MimeLimitExceeded): parse(value, MimeLimits(max_decoded_bytes=50))

    def test_filenames_cannot_escape_evidence_directory_or_collide(self):
        value = message()
        for data in (b'first', b'second'):
            value.add_attachment(data, maintype='application', subtype='octet-stream', filename='../../same.bin')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'attachments'
            output = scan_attachments(None, mime_result=parse(value), evidence_dir=root)
            self.assertEqual(len({item['evidence_path'] for item in output}), 2)
            self.assertEqual(len(list(root.iterdir())), 2)
            for item in output:
                saved = Path(temp)/item['evidence_path']
                self.assertTrue(saved.resolve().is_relative_to(root.resolve()))
                self.assertEqual(hashlib.sha256(saved.read_bytes()).hexdigest(), item['sha256'])

    def test_zip_metadata_is_bounded_and_not_decompressed(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('../escape.bin', b'x'*4096)
            archive.writestr('word/vbaProject.bin', b'Container entry, not proof of executable VBA')
        result = archive_inventory(data.getvalue(), max_total_size=1000)
        self.assertEqual(result['status'], 'limited')
        self.assertTrue(result['entries'][0]['unsafe_extraction_path'])
        self.assertEqual(result['macro_container_entries'], ['word/vbaProject.bin'])
        self.assertEqual(archive_inventory(data.getvalue(), max_entries=1)['status'], 'limited')

    def test_mime_and_attachment_processing_attempt_no_egress(self):
        value = message()
        value.add_attachment(b'harmless macro words VBA Project', maintype='application', subtype='msword', filename='document.doc')
        before = len(violations())
        with offline_policy(): output = scan_attachments(None, mime_result=parse(value))
        self.assertEqual(len(violations()), before)
        self.assertIsNone(output[0]['ole_macro'])


class ReviewRegressions(unittest.TestCase):
    def test_official_brand_identity_is_not_lookalike_risk(self):
        self.assertEqual(score_case({}, {}, {'domain':'paypal.com'}, headers={'from':'PayPal <service@paypal.com>'})['score'], 0)

    def test_brand_label_under_another_organizational_domain_is_not_exempt(self):
        self.assertGreater(score_case({}, {}, {'domain':'paypal.attacker.com'}, headers={'from':'PayPal <service@paypal.attacker.com>'})['score'], 0)

    def test_all_case_artifacts_are_indexed_and_added_files_fail_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'detonation/runs/one').mkdir(parents=True)
            (root/'detonation/runs/one/page.html').write_text('Real evidence bytes')
            (root/'execution.json').write_text('{}')
            index = seal_case(root)
            self.assertIn('execution.json', index)
            self.assertIn('detonation/runs/one/page.html', index)
            self.assertTrue(verify_case(root))
            (root/'extra.bin').write_bytes(b'New unindexed artifact')
            self.assertFalse(verify_case(root))
            (root/'extra.bin').unlink()
            (root/'detonation/runs/one/page.html').write_text('Altered evidence bytes')
            self.assertFalse(verify_case(root))

    def test_rekor_field_presence_does_not_establish_verified_proof(self):
        self.assertFalse(verify_inclusion_proof({'logIndex':0,'treeSize':1,'rootHash':'a'*64,'hashes':['b'*64]}, 'c'*64))


if __name__ == '__main__': unittest.main()
