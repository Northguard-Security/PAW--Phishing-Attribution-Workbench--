"""Header observations across parser nodes, with bounded raw/derived capture."""
import base64
from dataclasses import replace
from email import policy
from email.message import EmailMessage
import hashlib
import json
import unittest

from paw.core.header_inventory import inventory_headers
from paw.core.mime_analysis import MimeLimits, MimeLimitExceeded, analyze_mime
from paw.core.mime_header_inventory import MimeHeaderInventoryLimits, inventory_mime_headers, mime_header_coverage
from paw.core.network_policy import offline_policy
from paw.core.parser_mail import parse_message_bytes


def multipart(*entities, subtype='mixed'):
    return (f'Content-Type: multipart/{subtype}; boundary=b\r\nX-Root: outer\r\n\r\n'.encode()
        + b''.join(b'--b\r\n'+entity+b'\r\n' for entity in entities)+b'--b--\r\n')


class MimeHeaderInventoryTests(unittest.TestCase):
    def inventory(self, raw, **limits):
        return inventory_mime_headers(parse_message_bytes(raw), raw,
            replace(MimeHeaderInventoryLimits(), **limits))

    def test_recursive_ancestry_and_outer_attachment_binding(self):
        embedded = (b'From: inner@example.invalid\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n'
            b'--c\r\nX-Leaf: inner\r\n\r\nbody\r\n--c\r\nContent-Type: message/rfc822\r\n\r\n'
            b'From: deeper@example.invalid\r\nX-Deep: value\r\n\r\nbody\r\n--c--\r\n')
        raw = multipart(b'X-Leaf: outer\r\n\r\nbody',
            b'Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=nested.eml\r\n\r\n'+embedded)
        inventory = self.inventory(raw)
        parts = {p['part_id']:p for p in inventory['parts']}
        self.assertEqual(list(parts), ['0','0.0','0.1','0.1.0','0.1.0.0','0.1.0.1','0.1.0.1.0'])
        self.assertEqual(parts['0']['role'], 'outer_message')
        self.assertEqual(parts['0.1.0']['role'], 'encapsulated_message')
        for identifier in ('0.1.0','0.1.0.0','0.1.0.1'):
            self.assertEqual(parts[identifier]['message_root_part_id'], '0.1.0')
            self.assertEqual(parts[identifier]['enclosing_message_part_id'], '0.1')
            self.assertEqual(parts[identifier]['outer_mime_part_id'], '0.1')
        deep = parts['0.1.0.1.0']
        self.assertEqual(deep['parent_part_id'], '0.1.0.1')
        self.assertEqual(deep['message_root_part_id'], deep['part_id'])
        self.assertEqual(deep['enclosing_message_part_id'], '0.1.0.1')
        self.assertEqual(deep['outer_mime_part_id'], '0.1')
        self.assertEqual(inventory['status'], 'completed')

    def test_header_order_duplicate_scope_octets_and_legacy_root_equivalence(self):
        raw = multipart(b'X-Trace: one\r\nx-trace: two\r\nX-Fold: a\r\n\tb\r\n'
            b'Subject: =?utf-8?b?Y2Fmw6k=?=\r\nX-Raw: \xff\r\n\r\nX-Body: ignored')
        inventory = self.inventory(raw)
        root = inventory['parts'][0]['headers'].copy()
        root['scope'] = 'parser_recognized_top_level_headers'
        self.assertEqual(root, inventory_headers(parse_message_bytes(raw),raw))
        fields = inventory['parts'][1]['headers']['fields']
        self.assertEqual([f['occurrence_index'] for f in fields], [0,1,0,0,0])
        self.assertEqual(fields[3]['parsed_value'], 'café')
        self.assertEqual(base64.b64decode(fields[4]['raw_value_base64']),b'\xff')
        self.assertEqual(fields[4]['parsed_status'], 'partial')
        self.assertEqual(inventory['source']['sha256'],hashlib.sha256(raw).hexdigest())
        json.dumps(inventory,ensure_ascii=False).encode('utf-8')
        self.assertFalse(inventory['verified'])

    def test_delivery_blocks_external_body_unknown_types_and_digest(self):
        entities = [b'Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; host.invalid\r\n\r\n'
                    b'Final-Recipient: rfc822; user@example.invalid\r\nAction: failed\r\n',
                    b'Content-Type: message/external-body\r\n\r\nX-External: unverified\r\n\r\nbody',
                    b'Content-Type: application/x-unknown\r\nX-Unknown: kept\r\n\r\ndata']
        result = self.inventory(multipart(*entities))
        parts = {p['part_id']:p for p in result['parts']}
        for identifier in ('0.0.0','0.0.1','0.1.0'):
            self.assertEqual(parts[identifier]['role'],'parser_message_block')
            self.assertEqual(parts[identifier]['message_root_part_id'],identifier)
        self.assertEqual(parts['0.2']['headers']['fields'][1]['parsed_value'],'kept')
        digest = self.inventory(multipart(b'\r\nFrom: inner@example.invalid\r\n\r\nbody',subtype='digest'))
        self.assertEqual(digest['parts'][-1]['role'],'encapsulated_message')
        self.assertEqual(digest['parts'][-1]['part_id'],'0.0.0')

    def test_root_message_and_message_global_are_distinct_parser_roles(self):
        for content_type, role in (('message/rfc822','encapsulated_message'),('message/global','parser_message_block')):
            with self.subTest(content_type=content_type):
                result = self.inventory(f'Content-Type: {content_type}\r\n\r\nX-Inner: value\r\n\r\nbody'.encode())
                self.assertEqual(result['parts'][0]['role'],'outer_message')
                self.assertEqual(result['parts'][1]['role'],role)
                self.assertEqual(result['parts'][1]['outer_mime_part_id'],'0')

    def test_headerless_and_malformed_nodes_are_explicit(self):
        result = self.inventory(multipart(b'\r\nX-Body: ignored',b'X-Kept: value\r\nmalformed\r\nX-Body: ignored'))
        self.assertEqual(result['parts'][1]['headers']['fields'],[])
        malformed = result['parts'][2]['headers']
        self.assertEqual(malformed['total_field_count'],1)
        self.assertGreater(malformed['message_defect_count'],0)
        self.assertEqual(result['status'],'partial')

    def test_global_and_per_part_field_budgets(self):
        raw = multipart(*[b'X-A: first\r\nx-a: second\r\nX-B: third\r\n\r\nbody']*3)
        result = self.inventory(raw,max_fields=5,max_fields_per_part=2)
        self.assertEqual([p['headers']['inventoried_field_count'] for p in result['parts']],[2,2,1,0])
        self.assertEqual(result['total_field_count'],11)
        self.assertEqual(result['omitted_field_count'],6)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(mime_header_coverage(result)['omitted_field_count'],6)

    def test_raw_global_budget_counts_names_and_later_small_fields(self):
        raw = multipart(b'X-Long: 123456789\r\nX: a\r\n\r\nbody',b'Y: b\r\n\r\nbody')
        root_bytes = inventory_headers(parse_message_bytes(raw),raw)['captured_raw_bytes']
        result = self.inventory(raw,max_raw_bytes=root_bytes+2)
        self.assertEqual(result['captured_raw_bytes'],root_bytes+2)
        fields = result['parts'][1]['headers']['fields']
        self.assertEqual(fields[0]['raw_value_base64'],None)
        self.assertEqual(base64.b64decode(fields[1]['raw_value_base64']),b'a')
        self.assertIn('raw_byte_budget',result['parts'][2]['headers']['fields'][0]['issues'])
        per_part = self.inventory(raw,max_raw_bytes_per_part=2)
        self.assertEqual(per_part['captured_raw_bytes'],4)

    def test_utf8_derived_global_budget_preserves_raw_and_later_fitting_values(self):
        raw = b'X: \xff\xff\r\nY: a\r\nZ: b\r\n\r\nbody'
        result = self.inventory(raw,max_parsed_bytes=1)
        fields = result['parts'][0]['headers']['fields']
        self.assertEqual(base64.b64decode(fields[0]['raw_value_base64']),b'\xff\xff')
        self.assertEqual(fields[0]['parsed_value'],None)
        self.assertIn('parsed_byte_budget',fields[0]['issues'])
        self.assertEqual(fields[1]['parsed_value'],'a')
        self.assertEqual(fields[2]['parsed_value'],None)
        self.assertEqual(result['captured_parsed_bytes'],1)
        self.assertEqual(result['limited_field_count'],2)
        boundary = self.inventory(raw,max_parsed_bytes=6)
        self.assertEqual(boundary['captured_parsed_bytes'],6)
        self.assertEqual(boundary['parts'][0]['headers']['fields'][0]['parsed_value'],'\ufffd\ufffd')
        self.assertIsNone(boundary['parts'][0]['headers']['fields'][1]['parsed_value'])

    def test_encoded_message_payload_is_not_decoded_into_header_claims(self):
        for encoding,payload in (('base64',base64.b64encode(b'From: inner@example.invalid\r\n\r\nbody')),
                ('quoted-printable',b'From=3A inner@example.invalid\r\n\r\nbody')):
            with self.subTest(encoding=encoding):
                raw = (f'Content-Type: message/rfc822\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n'.encode()+payload)
                message = parse_message_bytes(raw)
                before = [(list(p.raw_items()),p.get_payload()) for p in message.walk()]
                result = inventory_mime_headers(message,raw)
                self.assertEqual(result['total_part_count'],2)
                self.assertEqual(result['parts'][1]['role'],'encapsulated_message')
                self.assertEqual(result['parts'][1]['headers']['fields'],[])
                self.assertEqual(result['parts'][1]['headers']['status'],'partial')
                self.assertEqual(before,[(list(p.raw_items()),p.get_payload()) for p in message.walk()])

    def test_name_value_limits_keep_positions_and_next_occurrences(self):
        result = self.inventory(b'Verylong: a\r\nX: toolong\r\nx: ok\r\n\r\nbody',max_name_bytes=2,max_value_bytes=2)
        fields = result['parts'][0]['headers']['fields']
        self.assertEqual(fields[0]['name'],None)
        self.assertEqual(fields[1]['occurrence_index'],0)
        self.assertEqual(fields[2]['occurrence_index'],1)
        self.assertEqual(fields[2]['parsed_value'],'ok')
        self.assertEqual(result['limited_field_count'],2)

    def test_part_depth_cutoff_counts_full_tree_and_keeps_later_siblings(self):
        raw = multipart(b'Content-Type: message/rfc822\r\n\r\nX-Inner: a\r\n\r\nbody',b'X-Outer: b\r\n\r\nbody')
        result = self.inventory(raw,max_depth=1)
        self.assertEqual([p['part_id'] for p in result['parts']],['0','0.0','0.1'])
        self.assertEqual(result['total_part_count'],4)
        self.assertEqual(result['omitted_part_count'],1)
        self.assertEqual(result['omitted_field_count'],1)
        self.assertEqual(result['issues'],['depth_limit'])
        count_limited = self.inventory(raw,max_parts=2)
        self.assertEqual(count_limited['omitted_part_count'],2)
        self.assertEqual(count_limited['omitted_field_count'],2)
        self.assertEqual(count_limited['issues'],['part_count_limit'])

    def test_existing_hard_tree_input_limits_include_embedded_nodes(self):
        raw = b'Content-Type: message/rfc822\r\n\r\nX: a\r\n\r\nbody'
        for limits in (MimeLimits(max_parts=1),MimeLimits(max_depth=0),MimeLimits(max_input_bytes=2)):
            with self.subTest(limits=limits), self.assertRaises(MimeLimitExceeded):
                inventory_mime_headers(parse_message_bytes(raw),raw,mime_limits=limits)

    def test_invalid_limits_and_zero_depth(self):
        for key in vars(MimeHeaderInventoryLimits()):
            for value in (True,1.5,-1):
                with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                    self.inventory(b'X: a\r\n\r\nbody',**{key:value})
            if key!='max_depth':
                with self.assertRaises(ValueError): self.inventory(b'X: a\r\n\r\nbody',**{key:0})
        result = self.inventory(multipart(b'X: a\r\n\r\nbody'),max_depth=0)
        self.assertEqual(result['omitted_part_count'],1)

    def test_offline_inventory_does_not_decode_mutate_or_promote_body_defects(self):
        raw = multipart(b'Content-Transfer-Encoding: base64\r\nX-Link: https://never.invalid/\r\n\r\nSGVsbG8')
        message = parse_message_bytes(raw)
        before = [(list(p.raw_items()),list(p.defects)) for p in message.walk()]
        with offline_policy(): result = inventory_mime_headers(message,raw)
        self.assertEqual(before,[(list(p.raw_items()),list(p.defects)) for p in message.walk()])
        self.assertEqual(result['status'],'completed')
        self.assertEqual(analyze_mime(message)['metadata']['status'],'partial')
        self.assertEqual(result['parts'][1]['headers']['message_defect_count'],0)

    def test_derived_factory_failure_keeps_raw_and_other_part(self):
        message = parse_message_bytes(multipart(b'X-Bad: kept\r\n\r\nbody',b'X-Good: kept\r\n\r\nbody'))
        def factory(name,value):
            if name=='X-Bad': raise ValueError('unsupported derived field')
            return policy.default.header_factory(name,value)
        message.get_payload()[0].policy = policy.default.clone(header_factory=factory)
        result = inventory_mime_headers(message,b'contract source')
        field = result['parts'][1]['headers']['fields'][0]
        self.assertEqual(base64.b64decode(field['raw_value_base64']),b'kept')
        self.assertEqual(field['parsed_status'],'unavailable')
        self.assertEqual(result['parts'][2]['headers']['status'],'completed')

    def test_non_wire_programmatic_octets_are_not_fabricated(self):
        message = EmailMessage(); message['X-Nonwire']='é'
        field = inventory_mime_headers(message,b'contract source')['parts'][0]['headers']['fields'][0]
        self.assertEqual(field['raw_status'],'unavailable')
        self.assertIsNone(field['raw_value_base64'])


if __name__ == '__main__': unittest.main()
