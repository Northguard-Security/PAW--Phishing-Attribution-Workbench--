"""Actual no-egress MIME body evidence through supervised CLI and HTTP workers."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import binascii
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.verify import verify_case


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def independent_bodies(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    stack = [(message,'0',False)]
    output = {}
    while stack:
        part, identifier, parent_attachment = stack.pop()
        attached = parent_attachment or part.get_content_disposition() == 'attachment' or bool(part.get_filename())
        container = part.is_multipart() and part.get_content_maintype() == 'multipart'
        if not attached and not container and part.get_content_type() in {'text/plain','text/html','text/javascript'}:
            output[identifier] = part.get_payload(decode=True)
            assert isinstance(output[identifier],bytes)
        payload = part.get_payload()
        if isinstance(payload,list) and part.get_content_maintype() != 'message':
            stack.extend((child,identifier+'.'+str(index),attached)
                for index,child in reversed(list(enumerate(payload))))
    return output


def check(case, raw, expected_status):
    assert (case/'input.eml').read_bytes() == raw
    assert verify_case(str(case))
    execution = read(case/'execution.json')
    assert execution['no_egress'] is True and not execution['blocked_operations']
    inventory = read(case/'mime_body_evidence.json')
    assert inventory['status'] == expected_status
    assert inventory['source'] == {'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()}
    assert inventory['verified'] is False
    expected = independent_bodies(raw)
    assert inventory['part_count'] == len(inventory['parts']) == len(expected)
    assert inventory['payload_bytes'] == sum(len(value) for value in expected.values())
    metadata = {p['part_id']:p for p in read(case/'mime_analysis.json')['parts']}
    assert {p['part_id'] for p in inventory['parts']} == set(expected)
    for field in inventory['parts']:
        body = expected[field['part_id']]
        assert field['size'] == len(body) and field['sha256'] == hashlib.sha256(body).hexdigest()
        assert field['sha256'] == metadata[field['part_id']]['sha256']
        assert field['decoding'] == metadata[field['part_id']]['decoding']
        assert field['defects'] == metadata[field['part_id']]['defects']
        assert field['byte_source'] == metadata[field['part_id']]['byte_source']
        assert field.get('transfer_decoding') == metadata[field['part_id']].get('transfer_decoding')
        assert field['payload_status'] == field['text_status'] == 'captured'
        for key in ('payload_path','text_path'):
            assert (case/field[key]).resolve().is_relative_to((case/'mime_body').resolve())
        assert (case/field['payload_path']).read_bytes() == body
        text = body.decode(field['decoding']['used_charset'],
            errors='replace' if field['decoding']['replacement_used'] else 'strict').encode('utf-8')
        assert (case/field['text_path']).read_bytes() == text
        assert field['text_sha256'] == hashlib.sha256(text).hexdigest() and field['text_size'] == len(text)
    coverage = read(case/'analysis_coverage.json')['stages']['mime_body_evidence']
    assert coverage == read(case/'report/score.json')['coverage']['stages']['mime_body_evidence']
    assert coverage['part_count'] == inventory['part_count'] and coverage['status'] == expected_status
    assert 'mime_body_evidence.json' in (case/'report/technical.md').read_text(encoding='utf-8')
    assert not (case.parent.parent/'unexpected-js-execution').exists()
    return inventory


def main():
    prefix = b'From: sender@example.invalid\r\nSubject: MIME body provenance\r\n'
    alternative = EmailMessage(policy=policy.SMTP)
    alternative['From'] = 'sender@example.invalid'; alternative['Subject'] = 'Body alternatives'
    alternative.set_content('Café plain',charset='iso-8859-1')
    alternative.add_alternative('<b>HTML one</b>',subtype='html')
    alternative.add_alternative('<i>HTML two</i>',subtype='html')
    nested = EmailMessage(policy=policy.SMTP)
    nested['From'] = 'sender@example.invalid'; nested.set_content('Outer body')
    inner = EmailMessage(policy=policy.SMTP)
    inner['From'] = 'inner@example.invalid'; inner.set_content('Inner body')
    nested.add_attachment(inner,filename='forward.eml')
    nested.add_attachment('Text attachment',filename='../../letter.txt')
    nested.add_attachment(b'PNG fixture',maintype='image',subtype='png',disposition='inline')
    truncated_uu = b'begin 644 fixture\r\n'+binascii.b2a_uu(b'Hello')
    inner = b'From: inner@example.invalid\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nCaf\xe9'
    embedded = b'Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename="a.eml"\r\n'
    invalid_embedded = embedded+b'Content-Transfer-Encoding: 7bit\r\n\r\n'+inner
    valid_embedded = embedded+b'Content-Transfer-Encoding: 8bit\r\n\r\n'+inner
    siblings = (b'Content-Type: multipart/mixed; boundary=nested\r\n\r\n--nested\r\n'+valid_embedded
                +b'\r\n--nested\r\n'+invalid_embedded+b'\r\n--nested--')
    samples = {
        'alternatives.eml':alternative.as_bytes(), 'nested.eml':nested.as_bytes(),
        'unknown-charset.eml':prefix+b'Content-Type: text/html; charset=unknown-charset\r\n\r\n<b>a\xffb</b>',
        'default-charset.eml':prefix+b'Content-Type: text/plain\r\n\r\na\xffb',
        'bad-base64.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8',
        'unknown-transfer.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: x-foo\r\n\r\nhello=3Dworld',
        'failed-base64.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nA',
        'failed-uuencode.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uue\r\n\r\nhello=3Dworld',
        'truncated-uuencode.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uue\r\n\r\n'+truncated_uu,
        'truncated-attachment-uuencode.eml':prefix+b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: x-uue\r\n\r\n'+truncated_uu,
        'bad-qp-eof.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=',
        'bad-qp-escape.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=G1',
        'bad-qp-softbreak.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=\rX',
        'bad-attachment-qp.eml':prefix+b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=',
        'invalid-7bit.eml':prefix+b'Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 7bit\r\n\r\nCaf\xe9',
        'invalid-default-7bit.eml':prefix+b'Content-Type: text/plain; charset=iso-8859-1\r\n\r\nCaf\xe9',
        'invalid-8bit-line.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'+b'a'*999,
        'invalid-7bit-attachment.eml':prefix+b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n\xff',
        'valid-8bit.eml':prefix+b'Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCaf\xe9\r\n',
        'valid-binary-body.eml':prefix+b'Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: binary\r\n\r\n'+bytes(range(256)),
        'valid-binary-attachment.eml':prefix+b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: binary\r\n\r\n'+bytes(range(256)),
        'embedded-invalid-7bit.eml':prefix+invalid_embedded,
        'embedded-valid-8bit.eml':prefix+valid_embedded,
        'embedded-invalid-8bit-header.eml':prefix+embedded+b'Content-Transfer-Encoding: 8bit\r\n\r\nFrom: '+b'a'*999+b'\r\n\r\nHello',
        'embedded-duplicate.eml':prefix+embedded+b'Content-Transfer-Encoding: 8bit\r\nContent-Transfer-Encoding: binary\r\n\r\n'+inner,
        'embedded-unhandled.eml':prefix+embedded+b'Content-Transfer-Encoding: base64\r\n\r\nRnJvbTogaW5uZXJAZXhhbXBsZS5pbnZhbGlkDQoNCkhlbGxv',
        'embedded-nested.eml':prefix+b'Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n'+siblings+b'\r\n--outer--\r\n',
        'duplicate-transfer.eml':prefix+b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nSGVsbG8=',
        'unknown-attachment-transfer.eml':prefix+b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: x-foo\r\n\r\nhello=3Dworld',
        'broken-multipart.eml':prefix+b'Content-Type: multipart/mixed; boundary=missing\r\n\r\nundelimited',
        'only-attachment.eml':prefix+b'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID',
        'javascript.eml':prefix+b'Content-Type: text/javascript\r\n\r\nrequire("fs").writeFileSync("unexpected-js-execution", "ran");',
        'empty.eml':prefix+b'Content-Type: text/plain\r\n\r\n'}
    partial = {'unknown-charset.eml','default-charset.eml','bad-base64.eml',
        'unknown-transfer.eml','failed-base64.eml','failed-uuencode.eml','duplicate-transfer.eml','truncated-uuencode.eml',
        'bad-qp-eof.eml','bad-qp-escape.eml','bad-qp-softbreak.eml',
        'invalid-7bit.eml','invalid-default-7bit.eml','invalid-8bit-line.eml'}
    transfer_sources = {'unknown-transfer.eml':'undecoded_unsupported_transfer_encoding',
        'failed-base64.eml':'undecoded_failed_transfer_encoding',
        'failed-uuencode.eml':'undecoded_failed_transfer_encoding',
        'truncated-uuencode.eml':'transfer_decoded_incomplete_framing',
        'bad-qp-eof.eml':'transfer_decoded_partial_syntax',
        'bad-qp-escape.eml':'transfer_decoded_partial_syntax',
        'bad-qp-softbreak.eml':'transfer_decoded_partial_syntax',
        'duplicate-transfer.eml':'derived_first_transfer_encoding',
        'invalid-7bit.eml':'identity_bytes_invalid_transfer_domain',
        'invalid-default-7bit.eml':'identity_bytes_invalid_transfer_domain',
        'invalid-8bit-line.eml':'identity_bytes_invalid_transfer_domain'}
    attachment_transfer = {
        'unknown-attachment-transfer.eml':('undecoded_unsupported_transfer_encoding',b'hello=3Dworld'),
        'truncated-attachment-uuencode.eml':('transfer_decoded_incomplete_framing',b'Hello'),
        'bad-attachment-qp.eml':('transfer_decoded_partial_syntax',b'Hello'),
        'invalid-7bit-attachment.eml':('identity_bytes_invalid_transfer_domain',b'\xff')}
    environment = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    def check_transfer(case, name, inventory):
        if name in transfer_sources:
            field, = inventory['parts']
            assert field['byte_source'] == transfer_sources[name]
            assert field['status'] == field['transfer_decoding']['status'] == 'partial'
            assert read(case/'mime_analysis.json')['status'] == 'partial'
        if name in {'truncated-uuencode.eml','bad-qp-eof.eml','bad-qp-softbreak.eml'}:
            field, = inventory['parts']
            assert (case/field['payload_path']).read_bytes() == b'Hello'
        if name in attachment_transfer:
            field, = read(case/'attachments.json')
            source, expected_payload = attachment_transfer[name]
            assert field['byte_source'] == source
            assert field['status'] == field['transfer_decoding']['status'] == 'partial'
            assert (case/field['evidence_path']).read_bytes() == expected_payload
            assert read(case/'mime_analysis.json')['status'] == 'partial'
            assert read(case/'analysis_coverage.json')['stages']['attachment_metadata']['status'] == 'partial'
        if name == 'valid-binary-attachment.eml':
            field, = read(case/'attachments.json')
            assert field['byte_source'] == 'transfer_decoded_bytes' and field['status'] == 'metadata_only'
            assert 'transfer_decoding' not in field
            assert (case/field['evidence_path']).read_bytes() == bytes(range(256))
            assert read(case/'mime_analysis.json')['status'] == 'completed'
        if name.startswith('embedded-'):
            # Derived serialization must remain distinct from the original
            # domain checked above; independently reproduce only that artifact.
            parsed = BytesParser(policy=policy.default).parsebytes(samples[name])
            parts = [part for part in parsed.walk() if part.get_content_type() == 'message/rfc822']
            expected_sources = {
                'embedded-invalid-7bit.eml':['derived_embedded_message_invalid_transfer_domain'],
                'embedded-valid-8bit.eml':['derived_embedded_message_serialization'],
                'embedded-invalid-8bit-header.eml':['derived_embedded_message_invalid_transfer_domain'],
                'embedded-duplicate.eml':['derived_embedded_message_transfer_unavailable'],
                'embedded-unhandled.eml':['derived_embedded_message_transfer_unavailable'],
                'embedded-nested.eml':['derived_embedded_message_serialization','derived_embedded_message_invalid_transfer_domain']}[name]
            fields = read(case/'attachments.json')
            assert len(fields) == len(parts) == len(expected_sources)
            for field, part, source in zip(fields, parts, expected_sources):
                expected = b'\r\n'.join(child.as_bytes() for child in part.get_payload())
                assert (case/field['evidence_path']).read_bytes() == expected
                assert field['byte_source'] == source
                valid = source == 'derived_embedded_message_serialization'
                assert field['status'] == ('metadata_only' if valid else 'partial')
                if not valid: assert field['transfer_decoding']['status'] == 'partial'
            status = 'completed' if name == 'embedded-valid-8bit.eml' else 'partial'
            assert read(case/'mime_analysis.json')['status'] == status
            if status == 'partial':
                assert read(case/'analysis_coverage.json')['stages']['attachment_metadata']['status'] == 'partial'
            assert inventory['part_count'] == 0
    with tempfile.TemporaryDirectory(prefix='paw-mime-body-',dir=REPO.parent) as temporary:
        base = Path(temporary).resolve(); inputs = base/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=base,env=environment,capture_output=True,timeout=150)
        assert result.returncode == 0,(result.stdout+result.stderr).decode(errors='replace')[-6000:]
        cases = list((base/'cases').glob('case-*')); assert len(cases) == len(samples)
        inventories = {}
        for case in cases:
            name = read(case/'manifest.json')['source_name']
            inventories[name] = check(case,samples[name],'partial' if name in partial else 'completed')
            check_transfer(case, name, inventories[name])
            if name == 'nested.eml':
                attachments = read(case/'attachments.json')
                assert len(attachments) == 3
                for field in attachments:
                    assert hashlib.sha256((case/field['evidence_path']).read_bytes()).hexdigest() == field['sha256']
                assert inventories[name]['part_count'] == 1
            if name == 'broken-multipart.eml':
                assert read(case/'mime_analysis.json')['status'] == 'partial'
                assert inventories[name]['part_count'] == 0
        assert inventories['alternatives.eml']['part_count'] == 3
        assert inventories['only-attachment.eml']['part_count'] == 0
        assert inventories['empty.eml']['payload_bytes'] == 0

        root = base/'http'; root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (base/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],cwd=root,
                env=dict(environment,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API bootstrap failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('alternatives.eml','unknown-charset.eml','unknown-transfer.eml','failed-uuencode.eml',
                             'unknown-attachment-transfer.eml','truncated-uuencode.eml','truncated-attachment-uuencode.eml',
                             'bad-qp-eof.eml','bad-attachment-qp.eml',
                             'invalid-7bit.eml','invalid-8bit-line.eml','invalid-7bit-attachment.eml',
                             'embedded-invalid-7bit.eml','embedded-nested.eml'):
                    raw = samples[name]; boundary = 'paw_mime_body_fixture'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded = json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload = {'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':120.0,'stage_seconds':60.0}}
                    job = json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end = time.monotonic()+140
                    while time.monotonic()<end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API worker')
                    assert state['status'] == 'completed' and state['supervisor']['tree_stopped'],state
                    case = root/'cases'/state['case_ids'][0]
                    inventory = check(case,raw,'partial' if name in partial else 'completed')
                    check_transfer(case, name, inventory)
                    assert json.loads(request('/api/cases/'+case.name))['mime_body_evidence'] == inventory
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('input.eml') == raw
                        assert json.loads(archive.read('mime_body_evidence.json')) == inventory
                        for field in inventory['parts']:
                            assert archive.read(field['payload_path']) == (case/field['payload_path']).read_bytes()
                            assert archive.read(field['text_path']) == (case/field['text_path']).read_bytes()
                        for field in read(case/'attachments.json'):
                            assert archive.read(field['evidence_path']) == (case/field['evidence_path']).read_bytes()
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: thirty-three actual full CLI cases and fourteen loopback HTTP workers; per-part bytes/charset text/provenance, alternatives, explicit partial transfer/charset decoding, unknown/failed/duplicate transfer declarations, truncated uuencode, malformed quoted-printable and identity transfer domains in bodies and attachments, embedded original-wire domain checks with unchanged derived serialization, valid 8bit/binary, nested/unsupported scope, empty and unexecuted JS sources, original MIME/seals/API ZIP. No-egress; not accuracy labels.')


if __name__ == '__main__': main()
