"""Actual offline workers; independent parser observations, tree links and exports."""
import base64
from collections import Counter
from email import policy
from email.parser import BytesParser
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


def parser_nodes(raw):
    """Independent preorder IDs; do not call PAW's inventory or traversal."""
    root = BytesParser(policy=policy.default).parsebytes(raw)
    stack = [(root,'0',None)]
    nodes = []
    while stack:
        part,identifier,parent = stack.pop()
        nodes.append((part,identifier,parent))
        payload = part.get_payload()
        if isinstance(payload,list):
            stack.extend((child,identifier+'.'+str(index),identifier)
                for index,child in reversed(list(enumerate(payload))))
    return nodes


def check_inventory(inventory,raw):
    nodes = parser_nodes(raw)
    assert inventory['verified'] is False
    assert inventory['scope']=='parser_recognized_mime_tree_headers'
    assert inventory['source']=={'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()}
    assert inventory['total_part_count']==len(nodes)==inventory['inventoried_part_count']
    assert inventory['omitted_part_count']==0
    assert inventory['total_field_count']==sum(len(part) for part,_,_ in nodes)
    raw_bytes = parsed_bytes = field_count = limited_count = 0
    contexts = {}
    for stored,(part,identifier,parent) in zip(inventory['parts'],nodes):
        assert stored['part_id']==identifier and stored['parent_part_id']==parent
        assert stored['depth']==identifier.count('.') and stored['content_type']==part.get_content_type()
        if parent is None:
            context = ('0',None,'0','outer_message')
        else:
            parent_part,parent_context = contexts[parent]
            message_root,enclosing,outer,_ = parent_context
            if parent_part.get_content_maintype()=='message':
                context = (identifier,parent,outer if enclosing is not None else parent,
                    'encapsulated_message' if parent_part.get_content_type()=='message/rfc822' else 'parser_message_block')
            else:
                context = (message_root,enclosing,outer if enclosing is not None else identifier,
                    'mime_container' if part.get_content_maintype()=='multipart' else 'mime_part')
        contexts[identifier] = (part,context)
        assert tuple(stored[key] for key in ('message_root_part_id','enclosing_message_part_id','outer_mime_part_id','role'))==context
        headers = stored['headers']; pairs = list(part.raw_items()); limits = inventory['limits']
        assert headers['source']==inventory['source'] and headers['verified'] is False
        assert headers['scope']=='parser_recognized_entity_headers'
        expected_count = min(len(pairs),limits['max_fields_per_part'],limits['max_fields']-field_count)
        assert len(headers['fields'])==expected_count
        assert headers['total_field_count']==len(pairs)
        assert headers['omitted_field_count']==len(pairs)-expected_count
        assert headers['message_defect_count']==len(part.defects)
        per_part_raw = per_part_parsed = 0; counts = Counter()
        for index,(field,(name,value)) in enumerate(zip(headers['fields'],pairs)):
            assert field['header_index']==index
            if len(name)>limits['max_name_bytes']:
                assert field['name'] is None and field['issues']==['name_size_limit']
                continue
            assert field['name']==name and field['normalized_name']==name.lower()
            assert field['occurrence_index']==counts[name.lower()]; counts[name.lower()]+=1
            octets = value.encode('ascii','surrogateescape'); size = len(name.encode('ascii'))+len(octets)
            expected_capture = (len(value)<=limits['max_value_bytes'] and
                per_part_raw+size<=limits['max_raw_bytes_per_part'] and raw_bytes+per_part_raw+size<=limits['max_raw_bytes'])
            assert (field['raw_status']=='captured')==expected_capture
            if not expected_capture:
                assert field['raw_value_base64'] is None and field['parsed_value'] is None and field['issues']
                continue
            assert base64.b64decode(field['raw_value_base64'],validate=True)==octets
            per_part_raw+=size
            parsed = part.policy.header_fetch_parse(name,value)
            derived = str(parsed).encode('utf-8','replace').decode('utf-8')
            expected_derived = (len(str(parsed))<=limits['max_value_bytes'] and
                parsed_bytes+per_part_parsed+len(derived.encode('utf-8'))<=limits['max_parsed_bytes'])
            if expected_derived:
                assert field['parsed_value']==derived
                per_part_parsed+=len(derived.encode('utf-8'))
                assert field['parsed_status']==('partial' if getattr(parsed,'defects',()) or not octets.isascii() or derived!=str(parsed) else 'completed')
            else:
                assert field['parsed_value'] is None and field['parsed_status']=='limited'
        assert headers['distinct_name_count']==len(counts)
        assert headers['duplicate_occurrence_count']==sum(count-1 for count in counts.values())
        assert headers['captured_raw_bytes']==per_part_raw
        assert headers['status']==('partial' if headers['issues'] or part.defects or
            any(f['raw_status']!='captured' or f['parsed_status']!='completed' for f in headers['fields']) else 'completed')
        raw_bytes+=per_part_raw; parsed_bytes+=per_part_parsed; field_count+=expected_count
        limited_count+=sum(f['raw_status']!='captured' or f['parsed_status']=='limited' for f in headers['fields'])
    assert inventory['captured_raw_bytes']==raw_bytes and inventory['captured_parsed_bytes']==parsed_bytes
    assert inventory['inventoried_field_count']==field_count
    assert inventory['limited_field_count']==limited_count
    assert inventory['omitted_field_count']==inventory['total_field_count']-field_count
    partial = sum(p['headers']['status']!='completed' for p in inventory['parts'])
    assert inventory['partial_part_count']==partial
    assert inventory['status']==('partial' if partial or inventory['issues'] else 'completed')
    return inventory


def check_case(case,raw):
    assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
    execution = read(case/'execution.json')
    assert execution['no_egress'] is True and not execution['blocked_operations']
    inventory = check_inventory(read(case/'mime_header_inventory.json'),raw)
    root = inventory['parts'][0]['headers'].copy()
    root['scope'] = 'parser_recognized_top_level_headers'
    assert root==read(case/'header_inventory.json')
    coverage = read(case/'analysis_coverage.json')['stages']['mime_header_inventory']
    assert coverage==read(case/'report/score.json')['coverage']['stages']['mime_header_inventory']
    for key in ('status','scope','verified','total_part_count','inventoried_part_count','omitted_part_count',
                'total_field_count','inventoried_field_count','omitted_field_count','limited_field_count','partial_part_count'):
        assert coverage[key]==inventory[key]
    assert coverage['artifact']=='mime_header_inventory.json'
    assert 'mime_header_inventory.json' in (case/'report/technical.md').read_text(encoding='utf-8')
    return inventory


def multipart(*entities,subtype='mixed'):
    return (f'From: outer@example.invalid\r\nContent-Type: multipart/{subtype}; boundary=b\r\n\r\n'.encode()
        +b''.join(b'--b\r\n'+entity+b'\r\n' for entity in entities)+b'--b--\r\n')


def main():
    embedded = (b'From: inner@example.invalid\r\nAuthentication-Results: attacker.invalid; dkim=pass\r\n'
        b'Content-Type: multipart/mixed; boundary=c\r\n\r\n--c\r\nX-Inner: kept\r\n\r\n'
        b'https://inner-body.invalid/\r\n--c\r\nContent-Type: message/rfc822\r\n\r\n'
        b'From: deeper@example.invalid\r\nX-Deep: kept\r\n\r\nbody\r\n--c--\r\n')
    family = multipart(b'Content-Type: multipart/alternative; boundary=a\r\nX-Container: kept\r\n\r\n'
        b'--a\r\nContent-Type: text/plain\r\nX-Part: first\r\nx-part: second\r\n\r\nbody\r\n'
        b'--a\r\nContent-Type: text/html\r\nX-Fold: first\r\n\tsecond\r\n\r\n<p>body</p>\r\n--a--\r\n',
        b'Content-Type: image/png\r\nContent-Disposition: inline; filename=image.png\r\nX-Inline: kept\r\n\r\ndata',
        b'Content-Type: text/plain\r\nContent-Disposition: attachment; filename=note.txt\r\nX-Attachment: kept\r\n\r\ndata',
        b'Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=nested.eml\r\n\r\n'+embedded)
    samples = {
        'family.eml':family,
        'high-bytes.eml':multipart(b'Subject: =?utf-8?b?Y2Fmw6k=?=\r\nX-Octets: \xff\xfe\r\n\r\nbody'),
        'malformed.eml':multipart(b'X-Kept: kept\r\nnot a header\r\nX-Body: ignored'),
        'headerless.eml':multipart(b'\r\nX-Body: ignored'),
        'message-blocks.eml':multipart(b'Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; host.invalid\r\n\r\nAction: failed\r\n',
            b'Content-Type: message/external-body\r\n\r\nX-External: kept\r\n\r\nbody',
            b'Content-Type: message/global\r\n\r\nX-Global: kept\r\n\r\nbody',
            b'Content-Type: application/x-unknown\r\nX-Unknown: kept\r\n\r\ndata'),
        'digest.eml':multipart(b'\r\nFrom: inner@example.invalid\r\nX-Digest: kept\r\n\r\nbody',subtype='digest'),
        'root-message.eml':b'From: outer@example.invalid\r\nContent-Type: message/rfc822\r\n\r\n'+embedded,
        'global-fields.eml':multipart(*[(b'X-Trace: value\r\n'*850)+b'\r\nbody']*5),
        'global-raw.eml':multipart(*[(b'X-Trace: '+b'a'*15000+b'\r\n')*16+b'\r\nbody']*5),
        'global-derived.eml':multipart(*[(b'X-Octets: '+b'\xff'*15000+b'\r\n')*16+b'\r\nbody']*4),
        'individual-limits.eml':multipart(b'X-'+b'a'*300+b': value\r\nX-Long: '+b'a'*17000+b'\r\nX: kept\r\n\r\nbody'),
        'body-decoding.eml':multipart(b'Content-Transfer-Encoding: base64\r\nX-Part: kept\r\n\r\nSGVsbG8')}
    env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-mime-headers-',dir=REPO.parent) as temporary:
        base = Path(temporary).resolve(); inputs = base/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','180','--stage-timeout','60','--memory-mib','1024'],
            cwd=base,env=env,capture_output=True,timeout=210)
        assert result.returncode==0,(result.stdout+result.stderr).decode(errors='replace')[-6000:]
        cases = list((base/'cases').glob('case-*')); assert len(cases)==len(samples)
        inventories = {}
        for case in cases:
            name = read(case/'manifest.json')['source_name']
            inventories[name] = check_case(case,samples[name])
            if name in {'family.eml','root-message.eml','digest.eml'}:
                assert read(case/'headers.json')['from']=='outer@example.invalid'
                assert read(case/'headers.json')['authentication_results']==[]
                assert 'inner-body.invalid' not in json.dumps(read(case/'url_evidence.json'))
            if name=='body-decoding.eml':
                assert inventories[name]['status']=='completed' and read(case/'mime_analysis.json')['status']=='partial'
        assert inventories['family.eml']['total_part_count']==11
        assert inventories['global-fields.eml']['inventoried_field_count']==4096
        assert inventories['global-fields.eml']['omitted_field_count']==156
        assert inventories['global-raw.eml']['limited_field_count']>0
        assert inventories['global-derived.eml']['captured_parsed_bytes']<=2097152
        assert any('parsed_byte_budget' in f['issues'] for p in inventories['global-derived.eml']['parts'] for f in p['headers']['fields'])

        root = base/'http'; root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (base/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],
                cwd=root,env=dict(env,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API bootstrap failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('family.eml','global-fields.eml','high-bytes.eml'):
                    raw = samples[name]; boundary='paw_mime_headers_fixture'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
                        +raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded = json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload = {'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':120.0,'stage_seconds':60.0}}
                    job = json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end = time.monotonic()+140
                    while time.monotonic()<end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case = root/'cases'/state['case_ids'][0]; inventory = check_case(case,raw)
                    assert json.loads(request('/api/cases/'+case.name))['mime_header_inventory']==inventory
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('input.eml')==raw
                        assert json.loads(archive.read('mime_header_inventory.json'))==inventory
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: 12 actual full CLI cases and three loopback HTTP workers; MIME/embedded/block header order, ancestry, raw/derived budgets, originals, seals, coverage, API and ZIP. Offline; fixtures are not classification truth.')


if __name__=='__main__': main()
