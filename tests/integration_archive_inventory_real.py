"""Actual offline CLI/HTTP attachment and bounded ZIP-declaration contracts."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import warnings
import zipfile
import zlib

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.verify import verify_case


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def make_zip(entries):
    buffer=io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore',UserWarning)
        with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for name,data in entries: archive.writestr(name,data)
    return buffer.getvalue()


def make_unicode_zip(entries, crc_valid=True):
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as archive:
        for legacy,name in entries:
            info=zipfile.ZipInfo(legacy)
            field=struct.pack('<BI',1,zlib.crc32(legacy.encode('ascii'))^(0 if crc_valid else 1))+name.encode('utf-8')
            info.extra=struct.pack('<HH',0x7075,len(field))+field
            archive.writestr(info,b'Unicode Path regression content')
    return buffer.getvalue()


def expected_unicode_paths(entry):
    """Independent extra-field walk; no PAW collector or sanitization helper."""
    result={'status':'completed','scope':'crc_matched_version_1_unicode_path_extra_values',
        'field_count':0,'matched_name_count':0,'ignored_field_count':0,
        'unsafe_name_count':0,'nul_name_count':0,'issues':[]}
    spelling=entry.orig_filename.encode('utf-8' if entry.flag_bits&0x800 else 'cp437')
    position=0
    while len(entry.extra)-position>=4:
        tag,length=struct.unpack('<HH',entry.extra[position:position+4])
        body=entry.extra[position+4:position+4+length]; position+=4+length
        assert len(body)==length
        if tag!=0x7075: continue
        result['field_count']+=1
        if len(body)<5:
            if 'malformed_unicode_path_extra' not in result['issues']: result['issues'].append('malformed_unicode_path_extra')
            continue
        version,crc=struct.unpack('<BI',body[:5])
        if version!=1 or crc!=zlib.crc32(spelling):
            result['ignored_field_count']+=1; continue
        try: name=body[5:].decode('utf-8')
        except UnicodeDecodeError:
            if 'invalid_unicode_path_utf8' not in result['issues']: result['issues'].append('invalid_unicode_path_utf8')
            continue
        result['matched_name_count']+=1
        view=name.replace('\\','/')
        result['unsafe_name_count']+=int(view.startswith('/') or '..' in view.split('/') or ':' in view or '\x00' in view)
        result['nul_name_count']+=int('\x00' in view)
    if result['issues']: result['status']='not_evaluated'
    return result


def check_archive(stored,payload):
    if not payload.startswith((b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08')):
        assert stored['status']=='not_evaluated'
        assert stored['reason']=='No supported ZIP prefix; ZIP membership not verified'; return
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive: entries=archive.infolist()
    except (zipfile.BadZipFile,ValueError,OSError,NotImplementedError):
        assert stored['status']=='error' and 'entries' not in stored; return
    assert stored['scope']=='parser_decoded_zip_central_directory_metadata' and stored['verified'] is False
    assert stored['entry_count']==len(entries)
    assert stored['inventoried_entry_count']==len(stored['entries'])==min(1000,len(entries))
    assert stored['omitted_entry_count']==max(0,len(entries)-1000)
    assert stored['declared_total_size']==sum(entry.file_size for entry in entries)
    names_bytes=limited_names=0; macro_names=[]; issues=[]
    if len(entries)>1000: issues.append('entry_count_limit')
    if sum(e.file_size for e in entries)>100*1024*1024: issues.append('declared_total_size_limit')
    for index,(field,entry) in enumerate(zip(stored['entries'],entries)):
        original=entry.orig_filename; size=len(original.encode('utf-8'))
        parser_size=len(entry.filename.encode('utf-8'))
        retained_size=size+(parser_size if entry.filename!=original else 0)
        keep=max(size,parser_size)<=4096 and names_bytes+retained_size<=262144
        assert field['entry_index']==index and field['declared_size']==entry.file_size
        assert field['compressed_size']==entry.compress_size and field['encrypted']==bool(entry.flag_bits&1)
        assert field['name_utf8_bytes']==size and field['name_normalized']==(entry.filename!=original)
        assert field['parser_name_utf8_bytes']==parser_size
        normalized=[view.replace('\\','/') for view in (original,entry.filename)]
        unsafe=any(view.startswith('/') or '..' in view.split('/') or ':' in view or '\x00' in view for view in normalized)
        extra_check=expected_unicode_paths(entry)
        assert field['unicode_path_check']==extra_check
        unsafe=unsafe or bool(extra_check['unsafe_name_count'])
        if extra_check['status']!='completed':
            if 'unicode_path_check_unavailable' not in issues: issues.append('unicode_path_check_unavailable')
            if not unsafe: unsafe=None
        assert field['unsafe_extraction_path']==unsafe
        if keep:
            assert field['name']==entry.filename and field['original_name']==original
            assert field['name_status']=='captured' and not field['name_issues']
            names_bytes+=retained_size
            if entry.filename.lower().endswith('vbaproject.bin'): macro_names.append(entry.filename)
        else:
            assert field['name'] is None and field['original_name'] is None
            assert field['name_status']=='limited'
            assert field['name_issues']==['entry_name_size_limit' if max(size,parser_size)>4096 else 'entry_name_byte_budget']
            limited_names+=1
        for issue in field['name_issues']:
            if issue not in issues: issues.append(issue)
    assert stored['captured_name_utf8_bytes']==names_bytes and stored['limited_name_count']==limited_names
    assert names_bytes<=262144
    assert all(len(field[key].encode('utf-8'))<=4096 for field in stored['entries']
        for key in ('name','original_name') if field[key] is not None)
    assert sum(len(field[key].encode('utf-8')) for field in stored['entries']
        for key in ('name','original_name') if field[key] is not None)<=2*names_bytes
    assert stored['macro_container_entries']==macro_names
    assert stored['macro_container_entries_scope']=='inventoried_entries_with_retained_parser_names'
    assert stored['issues']==issues
    limits=any(issue!='unicode_path_check_unavailable' for issue in issues)
    assert stored['status']==('limited' if limits else 'partial' if issues else 'metadata_only')


def check_case(case,raw):
    assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
    execution=read(case/'execution.json')
    assert execution['no_egress'] is True and not execution['blocked_operations']
    # Independent parser and transfer decode, no PAW MIME/attachment helper.
    message=BytesParser(policy=policy.default).parsebytes(raw)
    expected=[(part,'0.'+str(index)) for index,part in enumerate(message.get_payload()) if index]
    stored=read(case/'attachments.json'); assert len(stored)==len(expected)
    for item,(part,identifier) in zip(stored,expected):
        payload=part.get_payload(decode=True)
        assert item['part_id']==identifier and item['size']==len(payload)
        assert item['sha256']==hashlib.sha256(payload).hexdigest()
        assert (case/item['evidence_path']).resolve().is_relative_to((case/'attachments').resolve())
        assert (case/item['evidence_path']).read_bytes()==payload
        check_archive(item['archive'],payload)
        assert item['status']==('partial' if item['archive']['status'] in {'limited','error','partial'} else 'metadata_only')
        assert item['assessment_status']=='partial' and item['risk_score'] is None and item['ole_macro'] is None
        assert item['risk_level']=='not_evaluated'
        assert item['macro_analysis']['status']==item['mime_detection']['status']==item['malware_analysis']['status']=='not_evaluated'
    coverage=read(case/'analysis_coverage.json')['stages']['attachment_metadata']
    assert coverage==read(case/'report/score.json')['coverage']['stages']['attachment_metadata']
    assert coverage['count']==len(stored) and coverage['malware_analysis']=='not_evaluated'
    assert coverage['status']==('partial' if any(item['status']=='partial' for item in stored) else 'completed')
    assert 'inner-archive.invalid' not in json.dumps(read(case/'url_evidence.json'))
    return stored


def main():
    normal=make_zip([('first.txt',b'first'),('word/vbaProject.bin',b'Container name, not validated VBA')])
    over_count=make_zip([('file-%04d.txt'%index,b'data') for index in range(1001)])
    nul=make_zip([('file-0000.txt',b'data')]).replace(b'file-0000.txt',b'file\x000000.txt')
    large_declared=bytearray(make_zip([('small.txt',b'data')]))
    struct.pack_into('<I',large_declared,large_declared.index(b'PK\x01\x02')+24,101*1024*1024)
    unreadable=bytearray(make_zip([('crc.txt',b'data')]))
    struct.pack_into('<I',unreadable,unreadable.index(b'PK\x01\x02')+16,0)
    encrypted=bytearray(make_zip([('encrypted.txt',b'data')]))
    central=encrypted.index(b'PK\x01\x02'); struct.pack_into('<H',encrypted,central+8,1)
    struct.pack_into('<H',encrypted,central+10,99)
    unsupported=bytearray(normal)
    struct.pack_into('<H',unsupported,unsupported.index(b'PK\x01\x02')+6,99)
    payloads={
        'ordinary.eml':[normal], 'over-count.eml':[over_count], 'broken.eml':[b'PK\x03\x04broken'],
        'nul-name.eml':[nul], 'empty.eml':[make_zip([])],
        'large-name.eml':[make_zip([('n'*5000,b'x'),('small',b'y')])],
        'name-budget.eml':[make_zip([('file-%04d-'%index+'n'*2400,b'x') for index in range(120)])],
        'declared-size.eml':[bytes(large_declared)],'crc-unchecked.eml':[bytes(unreadable)],
        'encrypted-unknown.eml':[bytes(encrypted)],
        'unsupported-reader.eml':[normal,bytes(unsupported),normal],
        'prefixed.eml':[b'MZ harmless regression prefix'+normal],
        'nonzip.eml':[b'https://inner-archive.invalid/ Content is not a ZIP despite its MIME declaration'],
        'unicode-large.eml':[make_unicode_zip([('a','n'*5000+'vbaProject.bin')])],
        'unicode-budget.eml':[make_unicode_zip([(str(index),'n'*3000+'vbaProject.bin') for index in range(100)])],
        'unicode-paths.eml':[make_unicode_zip([('safe.txt','../evil.txt'),('../legacy','safe.txt')])],
        'unicode-ignored.eml':[make_unicode_zip([('safe.txt','../'+'n'*5000)],crc_valid=False)],
        'unicode-nul.eml':[make_unicode_zip([('safe','safe\x00../evil.txt'),('legacy','safe\x00'+'x'*5000)])],
        'unicode-nul-ignored.eml':[make_unicode_zip([('safe','safe\x00../evil.txt')],crc_valid=False)],
        'unicode-invalid.eml':[normal,make_unicode_zip([('safe','path')]).replace(b'path',b'pat\xff'),normal],
        'mixed.eml':[b'PK\x03\x04broken',normal,make_zip([('same',b'a'),('same',b'b'),('../path',b'')])]}
    samples={}
    for name,values in payloads.items():
        message=EmailMessage(policy=policy.SMTP)
        message['From']='outer@example.invalid'; message['Subject']='ZIP metadata contracts'
        message.set_content('Offline attachment scope')
        for payload in values: message.add_attachment(payload,maintype='application',subtype='zip',filename='../../same.zip')
        samples[name]=message.as_bytes()
    env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-archive-inventory-',dir=REPO.parent) as temporary:
        base=Path(temporary).resolve(); inputs=base/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        result=subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','180','--stage-timeout','60','--memory-mib','1024'],
            cwd=base,env=env,capture_output=True,timeout=210)
        assert result.returncode==0,(result.stdout+result.stderr).decode(errors='replace')[-6000:]
        cases=list((base/'cases').glob('case-*')); assert len(cases)==len(samples)
        inventories={}
        for case in cases:
            name=read(case/'manifest.json')['source_name']; inventories[name]=check_case(case,samples[name])
        assert len(inventories['over-count.eml'][0]['archive']['entries'])==1000
        assert inventories['over-count.eml'][0]['archive']['omitted_entry_count']==1
        assert inventories['nul-name.eml'][0]['archive']['entries'][0]['original_name']=='file\x000000.txt'
        assert inventories['nul-name.eml'][0]['archive']['entries'][0]['unsafe_extraction_path']
        assert inventories['name-budget.eml'][0]['archive']['limited_name_count']>0
        for field in inventories['unicode-nul.eml'][0]['archive']['entries']:
            assert field['unsafe_extraction_path'] is True and field['unicode_path_check']['nul_name_count']==1
        ignored=inventories['unicode-nul-ignored.eml'][0]['archive']['entries'][0]
        assert ignored['unsafe_extraction_path'] is False and ignored['unicode_path_check']['ignored_field_count']==1
        assert [item['status'] for item in inventories['unicode-invalid.eml']]==['metadata_only','partial','metadata_only']
        if sys.version_info >= (3,12):
            assert inventories['unicode-large.eml'][0]['archive']['limited_name_count']==1
            assert inventories['unicode-large.eml'][0]['archive']['macro_container_entries']==[]
            assert inventories['unicode-budget.eml'][0]['archive']['limited_name_count']>0
            assert inventories['unicode-paths.eml'][0]['archive']['entries'][0]['name']=='../evil.txt'
            assert inventories['unicode-paths.eml'][0]['archive']['entries'][0]['unsafe_extraction_path']
        else:
            assert inventories['unicode-large.eml'][0]['archive']['entries'][0]['name']=='a'

        root=base/'http'; root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (base/'http.log').open('wb') as log:
            server=subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],
                cwd=root,env=dict(env,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
            try:
                end=time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API bootstrap failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('over-count.eml','broken.eml','nul-name.eml','name-budget.eml','unsupported-reader.eml',
                             'unicode-large.eml','unicode-budget.eml','unicode-paths.eml',
                             'unicode-nul.eml','unicode-nul-ignored.eml','unicode-invalid.eml'):
                    raw=samples[name]; boundary='paw_archive_inventory_fixture'
                    upload=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
                        +raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded=json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload={'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':120.0,'stage_seconds':60.0}}
                    job=json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end=time.monotonic()+140
                    while time.monotonic()<end:
                        state=json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case=root/'cases'/state['case_ids'][0]; items=check_case(case,raw)
                    detail=json.loads(request('/api/cases/'+case.name))
                    assert detail['attachments']==items
                    assert detail['coverage']['stages']['attachment_metadata']['status']==('partial' if any(item['status']=='partial' for item in items) else 'completed')
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('input.eml')==raw
                        assert json.loads(archive.read('attachments.json'))==items
                        for item in items: assert archive.read(item['evidence_path'])==(case/item['evidence_path']).read_bytes()
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: 21 actual full CLI cases and eleven loopback HTTP workers; ZIP prefix/name budgets, both parser views and unsanitized Unicode Path observations, partial/unknown coverage, unsupported-reader continuation, member-metadata-only boundaries, exact payloads, seals, API and ZIP. Offline; constructed inputs are not accuracy labels.')


if __name__=='__main__': main()
