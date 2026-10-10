"""Actual ZIP metadata and original payloads; no member extraction or execution."""
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
import zlib
from email import policy
from email.message import EmailMessage

from paw.core.attach import archive_inventory, scan_attachments
from paw.core.mime_analysis import analyze_mime
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_message_bytes


def make_zip(entries):
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',UserWarning)
        with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_STORED) as archive:
            for name,data in entries: archive.writestr(name,data)
    return buffer.getvalue()


def make_unicode_zip(entries, version=1, crc_valid=True):
    """Actual Unicode Path extras with ASCII legacy central/local names."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as archive:
        for legacy,unicode_name in entries:
            info = zipfile.ZipInfo(legacy)
            crc = zlib.crc32(legacy.encode('utf-8')) ^ (0 if crc_valid else 1)
            data = struct.pack('<BI',version,crc)+unicode_name.encode('utf-8')
            info.extra = struct.pack('<HH',0x7075,len(data))+data
            archive.writestr(info,b'x')
    return buffer.getvalue()


class ArchiveInventoryTests(unittest.TestCase):
    def test_order_duplicates_and_empty_archive(self):
        result = archive_inventory(make_zip([('same',b'first'),('same',b'second'),('empty',b'')]))
        self.assertEqual(result['status'],'metadata_only')
        self.assertEqual([e['entry_index'] for e in result['entries']],[0,1,2])
        self.assertEqual([e['name'] for e in result['entries']],['same','same','empty'])
        self.assertEqual([e['declared_size'] for e in result['entries']],[5,6,0])
        self.assertEqual(result['entry_count'],3)
        self.assertEqual(result['omitted_entry_count'],0)
        self.assertFalse(result['verified'])
        empty = archive_inventory(make_zip([]))
        self.assertEqual(empty['status'],'metadata_only')
        self.assertEqual(empty['entries'],[])
        self.assertEqual(empty['declared_total_size'],0)

    def test_count_limit_preserves_prefix_and_counts_omitted_size(self):
        result = archive_inventory(make_zip([('a',b'a'),('b',b'bb'),('word/vbaProject.bin',b'xxx')]),max_entries=2,max_total_size=4)
        self.assertEqual(result['entry_count'],3)
        self.assertEqual(result['inventoried_entry_count'],2)
        self.assertEqual(result['omitted_entry_count'],1)
        self.assertEqual(result['declared_total_size'],6)
        self.assertEqual(result['issues'],['entry_count_limit','declared_total_size_limit'])
        self.assertEqual(result['macro_container_entries'],[])
        self.assertEqual(result['macro_container_entries_scope'],'inventoried_entries_with_retained_parser_names')

    def test_count_boundary_and_size_boundary(self):
        raw = make_zip([('a',b'abc'),('b',b'def')])
        self.assertEqual(archive_inventory(raw,max_entries=2,max_total_size=6)['status'],'metadata_only')
        limited = archive_inventory(raw,max_entries=1,max_total_size=5)
        self.assertEqual(limited['status'],'limited')
        self.assertEqual(limited['inventoried_entry_count'],1)

    def test_nul_suffix_preserved_and_original_path_checked(self):
        raw = make_zip([('file-0000.txt',b'x')]).replace(b'file-0000.txt',b'file\x000000.txt')
        result = archive_inventory(raw)
        entry = result['entries'][0]
        self.assertEqual(entry['name'],'file')
        self.assertEqual(entry['original_name'],'file\x000000.txt')
        self.assertTrue(entry['unsafe_extraction_path'])
        self.assertTrue(entry['name_normalized'])
        self.assertEqual(result['captured_name_utf8_bytes'],17)

    def test_unicode_extra_per_view_limits_and_macro_marker(self):
        raw = make_unicode_zip([('a','n'*5000+'vbaProject.bin')])
        result = archive_inventory(raw)
        if sys.version_info >= (3,12):
            entry = result['entries'][0]
            self.assertTrue(entry['name_normalized'])
            self.assertEqual(entry['parser_name_utf8_bytes'],5014)
            self.assertEqual(entry['name_issues'],['entry_name_size_limit'])
            self.assertIsNone(entry['name']); self.assertIsNone(entry['original_name'])
            self.assertEqual(result['captured_name_utf8_bytes'],0)
            self.assertEqual(result['macro_container_entries'],[])
        else:
            self.assertEqual(result['entries'][0]['name'],'a')
            self.assertEqual(result['status'],'metadata_only')

    def test_unicode_extra_budget_boundaries_and_later_short_name(self):
        raw = make_unicode_zip([('a','é'),('b','long'),('x','x')])
        result = archive_inventory(raw,max_total_name_bytes=4)
        if sys.version_info >= (3,12):
            self.assertEqual([e['name'] for e in result['entries']],['é',None,'x'])
            self.assertEqual(result['entries'][1]['name_issues'],['entry_name_byte_budget'])
            self.assertEqual(result['captured_name_utf8_bytes'],4)
            self.assertEqual(archive_inventory(make_unicode_zip([('a','é')]),max_name_bytes=2,
                max_total_name_bytes=3)['status'],'metadata_only')
            self.assertEqual(archive_inventory(make_unicode_zip([('a','é')]),max_total_name_bytes=2)['status'],'limited')
        else:
            self.assertEqual([e['name'] for e in result['entries']],['a','b','x'])

    def test_short_unicode_view_cannot_hide_long_original(self):
        result = archive_inventory(make_unicode_zip([('long-legacy','x')]),max_name_bytes=2)
        self.assertEqual(result['entries'][0]['name_issues'],['entry_name_size_limit'])
        self.assertIsNone(result['entries'][0]['name'])

    def test_unicode_extra_checks_both_path_views_even_when_limited(self):
        for legacy,name in (('safe.txt','../evil.txt'),('safe.txt','..\\evil.txt'),
                            ('safe.txt','/absolute'),('safe.txt','C:/drive'),('../legacy','safe.txt')):
            for budget in (1,4096):
                with self.subTest(legacy=legacy,name=name,budget=budget):
                    entry = archive_inventory(make_unicode_zip([(legacy,name)]),max_name_bytes=budget)['entries'][0]
                    self.assertTrue(entry['unsafe_extraction_path'])
                    if budget==1: self.assertIsNone(entry['name'])

    def test_invalid_unicode_extra_crc_and_version_do_not_replace_parser_name(self):
        for options in ({'crc_valid':False},{'version':2}):
            result = archive_inventory(make_unicode_zip([('safe','../'+'x'*5000)],**options))
            entry = result['entries'][0]
            self.assertEqual(entry['name'],'safe')
            self.assertFalse(entry['unsafe_extraction_path'])
            self.assertEqual(result['captured_name_utf8_bytes'],4)
            self.assertEqual(result['status'],'metadata_only')

    def test_unicode_nul_observed_before_sanitization_even_when_names_match_or_omitted(self):
        for legacy,name in (('safe','safe\x00../evil.txt'),('legacy','safe\x00'+'x'*5000)):
            for budget in (1,4096):
                with self.subTest(legacy=legacy,budget=budget):
                    result = archive_inventory(make_unicode_zip([(legacy,name)]),max_name_bytes=budget)
                    entry = result['entries'][0]
                    self.assertTrue(entry['unsafe_extraction_path'])
                    self.assertEqual(entry['unicode_path_check'],{
                        'status':'completed','scope':'crc_matched_version_1_unicode_path_extra_values',
                        'field_count':1,'matched_name_count':1,'ignored_field_count':0,
                        'unsafe_name_count':1,'nul_name_count':1,'issues':[]})
                    if budget==1: self.assertIsNone(entry['name'])
                    if sys.version_info >= (3,12) and legacy=='safe':
                        self.assertFalse(entry['name_normalized'])

    def test_unicode_nul_with_wrong_crc_or_version_is_ignored(self):
        for options in ({'crc_valid':False},{'version':2}):
            entry = archive_inventory(make_unicode_zip([('safe','safe\x00../evil.txt')],**options))['entries'][0]
            self.assertFalse(entry['unsafe_extraction_path'])
            self.assertEqual(entry['unicode_path_check']['ignored_field_count'],1)
            self.assertEqual(entry['unicode_path_check']['nul_name_count'],0)

    def test_unicode_extra_crc_binding_utf8_cp437_and_multiple_declarations(self):
        raw = make_unicode_zip([('é','safe\x00../evil.txt')])
        self.assertTrue(archive_inventory(raw)['entries'][0]['unsafe_extraction_path'])
        raw = make_unicode_zip([('cafx','safe\x00../evil.txt')])
        raw = raw.replace(b'cafx',b'caf\x82').replace(struct.pack('<I',zlib.crc32(b'cafx')),
            struct.pack('<I',zlib.crc32(b'caf\x82')))
        entry = archive_inventory(raw)['entries'][0]
        self.assertEqual(entry['original_name'],'café')
        self.assertEqual(entry['unicode_path_check']['matched_name_count'],1)
        self.assertTrue(entry['unsafe_extraction_path'])
        info = zipfile.ZipInfo('safe')
        fields = []
        for name in ('safe\x00../evil.txt','safe'):
            data = struct.pack('<BI',1,zlib.crc32(b'safe'))+name.encode('utf-8')
            fields.append(struct.pack('<HH',0x7075,len(data))+data)
        info.extra = b''.join(fields)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive: archive.writestr(info,b'x')
        entry = archive_inventory(buffer.getvalue())['entries'][0]
        self.assertEqual(entry['name'],'safe')
        self.assertEqual(entry['unicode_path_check']['matched_name_count'],2)
        self.assertTrue(entry['unsafe_extraction_path'])

    def test_unreadable_unicode_extra_is_unknown_not_safe_on_older_reader(self):
        info = zipfile.ZipInfo('safe'); info.extra = struct.pack('<HHB',0x7075,1,1)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive: archive.writestr(info,b'x')
        for raw in (make_unicode_zip([('safe','path')]).replace(b'path',b'pat\xff'),
                    buffer.getvalue()):
            result = archive_inventory(raw)
            if sys.version_info >= (3,12):
                self.assertEqual(result['status'],'error')
            else:
                self.assertEqual(result['status'],'partial')
                entry = result['entries'][0]
                self.assertIsNone(entry['unsafe_extraction_path'])
                self.assertEqual(entry['unicode_path_check']['status'],'not_evaluated')

    def test_unsafe_paths_and_original_separator_view(self):
        names = ('../a','dir/../a','/absolute','C:/drive','..\\escape','safe/a')
        raw = make_zip([(name,b'x') for name in names]).replace(b'../escape',b'..\\escape')
        result = archive_inventory(raw)
        self.assertEqual([e['original_name'] for e in result['entries']],list(names))
        self.assertEqual([e['unsafe_extraction_path'] for e in result['entries']],[True]*5+[False])

    def test_name_byte_limits_null_values_without_losing_member_metadata(self):
        result = archive_inventory(make_zip([('long-name',b'one'),('é',b'two'),('a',b'')]),max_name_bytes=2)
        entry = result['entries'][0]
        self.assertIsNone(entry['name']); self.assertIsNone(entry['original_name'])
        self.assertEqual(entry['name_issues'],['entry_name_size_limit'])
        self.assertEqual(entry['declared_size'],3)
        self.assertEqual(result['entries'][1]['original_name'],'é')
        self.assertEqual(result['captured_name_utf8_bytes'],3)
        self.assertEqual(result['limited_name_count'],1)

    def test_global_utf8_budget_uses_octets_and_allows_later_short_name(self):
        result = archive_inventory(make_zip([('é',b'a'),('big',b'b'),('x',b'c'),('y',b'd')]),max_total_name_bytes=3)
        self.assertEqual([e['name'] for e in result['entries']],['é',None,'x',None])
        self.assertEqual(result['captured_name_utf8_bytes'],3)
        self.assertEqual(result['limited_name_count'],2)
        self.assertEqual(result['entries'][3]['name_issues'],['entry_name_byte_budget'])
        self.assertEqual(result['declared_total_size'],4)
        self.assertEqual(result['status'],'limited')

    def test_omitted_name_does_not_bypass_budget_with_macro_marker(self):
        result = archive_inventory(make_zip([('word/vbaProject.bin',b'not validated VBA'),('a',b'')]),max_name_bytes=1)
        self.assertEqual(result['macro_container_entries'],[])
        self.assertEqual(result['entries'][1]['original_name'],'a')
        self.assertEqual(result['captured_name_utf8_bytes'],1)

    def test_missing_name_still_reports_unsafe_original_path(self):
        entry = archive_inventory(make_zip([('../long-name',b'one')]),max_name_bytes=2)['entries'][0]
        self.assertIsNone(entry['original_name'])
        self.assertTrue(entry['unsafe_extraction_path'])

    def test_invalid_limits_rejected(self):
        for name in ('max_entries','max_total_size','max_name_bytes','max_total_name_bytes'):
            for value in (True,0,-1,1.5,'1'):
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):
                    archive_inventory(make_zip([]),**{name:value})

    def test_unrecognized_prefix_does_not_assert_container_absence(self):
        raw = b'MZ harmless regression prefix'+make_zip([('file',b'content')])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(len(archive.infolist()),1)
        result = archive_inventory(raw)
        self.assertEqual(result['status'],'not_evaluated')
        self.assertEqual(result['reason'],'No supported ZIP prefix; ZIP membership not verified')

    def test_invalid_utf8_central_name_is_explicit_reader_error(self):
        raw = bytearray(make_zip([('file',b'content')]).replace(b'file',b'fil\xff'))
        central = raw.index(b'PK\x01\x02'); struct.pack_into('<H',raw,central+8,0x800)
        with self.assertRaises(UnicodeDecodeError): zipfile.ZipFile(io.BytesIO(raw))
        result = archive_inventory(bytes(raw))
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['reason'],'UnicodeDecodeError')

    def test_unsupported_reader_preserves_all_attachment_metadata_and_bytes(self):
        normal = make_zip([('file',b'content')]); unsupported = bytearray(normal)
        struct.pack_into('<H',unsupported,unsupported.index(b'PK\x01\x02')+6,99)
        with self.assertRaises(NotImplementedError): zipfile.ZipFile(io.BytesIO(unsupported))
        message = EmailMessage(policy=policy.SMTP); message.set_content('outer')
        values = (normal,bytes(unsupported),normal)
        for payload in values: message.add_attachment(payload,maintype='application',subtype='zip',filename='same.zip')
        with tempfile.TemporaryDirectory() as temporary,offline_policy():
            result = scan_attachments(None,mime_result=analyze_mime(parse_message_bytes(message.as_bytes())),evidence_dir=Path(temporary)/'attachments')
            self.assertEqual([r['status'] for r in result],['metadata_only','partial','metadata_only'])
            self.assertEqual(result[1]['archive'],{'status':'error','reason':'NotImplementedError'})
            for item,payload in zip(result,values):
                self.assertEqual((Path(temporary)/item['evidence_path']).read_bytes(),payload)

    def test_unreadable_member_crc_is_not_claimed_as_verified_content(self):
        raw = bytearray(make_zip([('file',b'content')]))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entry = archive.infolist()[0]
            offset = entry.header_offset+30+len(entry.filename.encode())+len(entry.extra)
        raw[offset] ^= 1
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            with self.assertRaises(zipfile.BadZipFile): archive.read('file')
        result = archive_inventory(bytes(raw))
        self.assertEqual(result['status'],'metadata_only')
        self.assertFalse(result['verified'])
        self.assertIn('member integrity',result['limitation'])

    def test_encryption_and_unknown_compression_are_declarations_only(self):
        raw = bytearray(make_zip([('file',b'content')]))
        central = raw.index(b'PK\x01\x02')
        struct.pack_into('<H',raw,central+8,1)
        struct.pack_into('<H',raw,central+10,99)
        result = archive_inventory(bytes(raw))
        self.assertTrue(result['entries'][0]['encrypted'])
        self.assertEqual(result['status'],'metadata_only')
        self.assertFalse(result['verified'])

    def test_error_and_count_limits_propagate_without_losing_other_attachments(self):
        message = EmailMessage(policy=policy.SMTP); message.set_content('outer')
        values = (b'PK\x03\x04broken',make_zip([('file-%04d'%i,b'') for i in range(1001)]),make_zip([]),b'ordinary non-ZIP')
        for payload in values:
            message.add_attachment(payload,maintype='application',subtype='octet-stream',filename='../same.bin')
        raw = message.as_bytes(); before = len(violations())
        with tempfile.TemporaryDirectory() as temporary,offline_policy():
            result = scan_attachments(None,mime_result=analyze_mime(parse_message_bytes(raw)),evidence_dir=Path(temporary)/'attachments')
            self.assertEqual([r['status'] for r in result],['partial','partial','metadata_only','metadata_only'])
            self.assertEqual([r['archive']['status'] for r in result],['error','limited','metadata_only','not_evaluated'])
            self.assertEqual(len({r['evidence_path'] for r in result}),4)
            for item,payload in zip(result,values):
                self.assertEqual((Path(temporary)/item['evidence_path']).read_bytes(),payload)
                self.assertEqual(item['sha256'],hashlib.sha256(payload).hexdigest())
                self.assertIsNone(item['risk_score']); self.assertIsNone(item['ole_macro'])
            self.assertEqual(len(violations()),before)


if __name__=='__main__': unittest.main()
