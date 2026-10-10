"""Local API: real analysis workers, persisted status, no simulated completion.
Run one API process. Each job executes in a separate Python process.
"""
import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import uuid
import time
from contextlib import asynccontextmanager, closing
from typing import Literal
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from urllib.parse import urlsplit
from pydantic import BaseModel, Field
from ..core.runtime import RunLimits, supervise, preserve_interrupted, read_progress
from ..core.process_recovery import recover_worker, identity_alive
from ..core.job_registry import control_path, case_owner, job_state, controls
from ..core.dkim_keys import snapshot_key_bundle
from ..core.index import describe_fingerprint

@asynccontextmanager
async def lifespan(application):
    # Recover before accepting requests; a killed API may leave POSIX writers.
    identifiers = {path.stem for path in JOBS_DIR.glob('analysis_*.json') if path.stem[9:].isalnum()}
    identifiers.update(identifier for identifier,_ in controls(DATA_DIR,JOBS_DIR))
    for identifier in identifiers:
        await get_analysis_status(identifier)
    yield

app = FastAPI(title='PAW', version='2.0.0', lifespan=lifespan)
STATIC_DIR = Path(__file__).parent/'static'
app.mount('/assets', StaticFiles(directory=STATIC_DIR), name='assets')

@app.middleware('http')
async def local_boundary(request: Request, call_next):
    host = request.headers.get('host', '')
    if urlsplit('//'+host).hostname not in {'127.0.0.1','localhost','::1'}:
        return JSONResponse({'detail':'Local host required'}, status_code=403)
    origin = request.headers.get('origin')
    if origin and origin != str(request.base_url).rstrip('/'):
        return JSONResponse({'detail':'Same-origin requests required'}, status_code=403)
    response = await call_next(request)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response
DATA_DIR = Path(os.environ.get('PAW_DATA_DIR', '.')).resolve()
CASES_DIR = DATA_DIR / 'cases'
UPLOAD_DIR = DATA_DIR / 'uploads'
JOBS_DIR = DATA_DIR / 'jobs'
EXPORT_DIR = DATA_DIR / 'exports'
for directory in (UPLOAD_DIR, JOBS_DIR, EXPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
analysis_queue = {}
_workers = asyncio.Semaphore(1)
MAX_ANALYSIS_SECONDS = 900
_cancel_events = {}
_recovery_locks = {}
UNSTABLE_CASE_STATUSES = {'queued','running','recovery_blocked'}

class RuntimeOptions(BaseModel):
    wall_seconds: float = Field(default=900, gt=0, le=3600, strict=True)
    stage_seconds: float = Field(default=120, gt=0, le=900, strict=True)
    memory_bytes: int = Field(default=2*1024**3, ge=64*1024**2, le=4*1024**3, strict=True)
    artifact_bytes: int = Field(default=512*1024**2, ge=1024, le=512*1024**2, strict=True)
    artifact_files: int = Field(default=10000, ge=1, le=10000, strict=True)
    log_bytes: int = Field(default=8*1024**2, ge=1024, le=8*1024**2, strict=True)
    model_config = {'extra':'forbid'}

@asynccontextmanager
async def job_slot(analysis_id, limits):
    job = analysis_queue[analysis_id]
    acquired = False
    allowed = False
    acquire_task = cancel_task = None
    try:
        remaining = limits.wall_seconds - (time.monotonic()-job['queued_monotonic'])
        if remaining > 0:
            acquire_task = asyncio.create_task(_workers.acquire())
            cancel_task = asyncio.create_task(_cancel_events[analysis_id].wait())
            done, _ = await asyncio.wait([acquire_task,cancel_task],timeout=remaining,return_when=asyncio.FIRST_COMPLETED)
            if cancel_task in done:
                job.update(status='cancelled',completed_at=now())
            elif acquire_task in done:
                acquired = allowed = True
            elif job['status'] == 'queued':
                job.update(status='timed_out',error='Queue deadline exceeded',completed_at=now())
        elif job['status'] == 'queued':
            job.update(status='timed_out',error='Queue deadline exceeded',completed_at=now())
        yield allowed
    except asyncio.CancelledError:
        if job['status'] == 'queued': job.update(status='interrupted',error='API stopped',completed_at=now())
        raise
    finally:
        tasks = [task for task in (acquire_task,cancel_task) if task is not None]
        for task in tasks:
            if not task.done(): task.cancel()
        if tasks: await asyncio.gather(*tasks,return_exceptions=True)
        if acquire_task is not None and not acquire_task.cancelled() and acquire_task.exception() is None:
            acquired = bool(acquire_task.result())
        if acquired: _workers.release()
        if not allowed:
            save(JOBS_DIR/(analysis_id+'.json'),job)
            _cancel_events.pop(analysis_id,None)
            analysis_queue.pop(analysis_id,None)

def now():
    return datetime.now(timezone.utc).isoformat()

def load(path):
    return json.loads(path.read_text(encoding='utf-8'))

def artifact(path, errors):
    try: return load(path)
    except (OSError, ValueError) as exc:
        errors[path.name] = type(exc).__name__ + ': ' + str(exc)
        return None

def save(path, data):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, indent=2), encoding='utf-8')
    temporary.replace(path)

def contained(root, value):
    path = Path(value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise HTTPException(400, 'Path outside allowed directory')
    return path

def case_path(case_id):
    if Path(case_id).name != case_id:
        raise HTTPException(400, 'Invalid case ID')
    path = contained(CASES_DIR, CASES_DIR / case_id)
    if not path.is_dir():
        raise HTTPException(404, 'Case not found')
    return path

def case_status(directory):
    """Completed requires worker acknowledgment, not a preliminary execution file."""
    execution = read_progress(directory/'execution.json')
    job_id = case_job_id(directory)
    if job_id:
        if not job_id.startswith('analysis_') or not job_id[9:].isalnum(): return 'incomplete'
        try: job = job_state(DATA_DIR,JOBS_DIR,job_id)
        except FileNotFoundError: return 'recovery_blocked'
        status = job.get('status', 'interrupted')
        if job.get('origin') == 'cli' and status in {'running','queued'}:
            return status  # get_analysis_status establishes live-owner or recovery first.
        if job_id not in analysis_queue and (
                status in {'running','queued','recovery_blocked'} or
                read_progress(control_path(DATA_DIR,JOBS_DIR,job_id)/'supervisor.json').get('tree_stopped') is not True):
            return 'recovery_blocked'
        if status == 'completed':
            return 'completed' if directory.name in job.get('case_ids', []) else 'incomplete'
        if any(item.get('case_id') == directory.name and item.get('status') == 'completed'
                and item.get('integrity') == 'verified' for item in job.get('partial_cases', [])):
            return 'completed'
        return status
    if execution.get('status') == 'completed':
        from ..core.verify import verify_case
        try: return 'completed' if verify_case(directory) else 'incomplete'
        except (OSError, ValueError, KeyError, TypeError): return 'incomplete'
    return execution.get('status', 'incomplete')

def case_job_id(directory):
    return case_owner(directory,DATA_DIR,JOBS_DIR)

async def stable_case_status(directory):
    job_id = case_job_id(directory)
    if job_id:
        await get_analysis_status(job_id)
    return case_status(directory)

async def require_stable_case(directory):
    status = await stable_case_status(directory)
    if status in UNSTABLE_CASE_STATUSES:
        raise HTTPException(409,'Worker shutdown not confirmed; evidence access blocked')
    return status

class AnalysisRequest(BaseModel):
    file_path: str
    profile: Literal['default', 'strict', 'conservative'] = 'default'
    options: dict = Field(default_factory=dict)
    limits: RuntimeOptions = Field(default_factory=RuntimeOptions)

class CaseQuery(BaseModel):
    query_type: Literal['ip', 'domain', 'asn']
    value: str

@app.get('/', include_in_schema=False)
async def workspace():
    return FileResponse(STATIC_DIR/'index.html')

@app.get('/health')
async def root():
    return {'name':'PAW', 'version':'2.0.0', 'status':'operational', 'timestamp':now()}

@app.post('/api/upload')
async def upload_email(file: UploadFile = File(...)):
    extension = Path(file.filename or '').suffix.lower()
    if extension not in {'.eml', '.msg'}:
        raise HTTPException(400, 'Only .eml and .msg files supported')
    path = UPLOAD_DIR / (uuid.uuid4().hex + extension)
    size = 0
    try:
        with path.open('xb') as stream:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > 25 * 1024 * 1024:
                    raise HTTPException(413, 'Email exceeds 25 MiB')
                stream.write(chunk)
        if not size: raise HTTPException(400, 'Empty email')
    except Exception:
        path.unlink(missing_ok=True)
        raise
    original_name = Path((file.filename or '').replace('\\','/')).name
    save(path.with_suffix(path.suffix+'.json'),{'filename':original_name})
    return {'status':'success', 'filename':path.name, 'original_name':original_name, 'path':str(path), 'size':size}

@app.post('/api/analyze')
async def analyze_email(request: AnalysisRequest, background_tasks: BackgroundTasks):
    if len(_cancel_events) >= 32: raise HTTPException(429, 'Analysis queue is full')
    path = Path(request.file_path)
    path = contained(UPLOAD_DIR, path if path.is_absolute() else DATA_DIR / path)
    if not path.is_file(): raise HTTPException(404, 'Uploaded email not found')
    if path.suffix.lower() not in {'.eml','.msg'}: raise HTTPException(400,'Unsupported email format')
    if set(request.options) - {'no_egress','stix','abuse','anchor','lang','dkim_keys'}:
        raise HTTPException(400, 'Unsupported options')
    for name in {'no_egress','stix','abuse','anchor'} & request.options.keys():
        if type(request.options[name]) is not bool:
            raise HTTPException(400, f'{name} must be boolean')
    options = dict(request.options)
    if 'dkim_keys' in options:
        try: options['dkim_key_evidence'] = snapshot_key_bundle(options.pop('dkim_keys'))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise HTTPException(400, 'Invalid local DKIM key evidence') from exc
    analysis_id = 'analysis_' + uuid.uuid4().hex
    job = {'status':'queued', 'file':str(path), 'filename':read_progress(path.with_suffix(path.suffix+'.json')).get('filename',path.name), 'no_egress':request.options.get('no_egress',True), 'queued_at':now(), 'queued_monotonic':time.monotonic(), 'progress':None}
    analysis_queue[analysis_id] = job
    _cancel_events[analysis_id] = asyncio.Event()
    job['limits'] = request.limits.model_dump()
    save(JOBS_DIR / (analysis_id + '.json'), job)
    background_tasks.add_task(run_analysis, analysis_id, path, request.profile, options, request.limits)
    return {'status':'queued', 'analysis_id':analysis_id}

async def run_analysis(analysis_id, path, profile, options, limits):
    async with job_slot(analysis_id, limits) as acquired:
        if not acquired: return
        job = analysis_queue[analysis_id]
        state = JOBS_DIR / (analysis_id + '.json')
        if job['status'] != 'queued':
            _cancel_events.pop(analysis_id, None)
            analysis_queue.pop(analysis_id, None)
            return
        request = JOBS_DIR / (analysis_id + '.request.json')
        result_path = JOBS_DIR / (analysis_id + '.result.json')
        save(request, dict(options, file_path=str(path), profile=profile,
            no_egress=options.get('no_egress', True)))
        control = JOBS_DIR / analysis_id
        try:
            job.update(status='running', started_at=now())
            save(state, job)
            env = dict(os.environ, PYTHONIOENCODING='utf-8')
            env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2])
            env['PAW_ANALYSIS_ID'] = analysis_id
            # DATA_DIR holds evidence, not trusted Python modules/dependencies.
            outcome = await supervise([sys.executable, '-P', '-X', 'utf8', '-m', 'paw.web.worker', str(request), str(result_path)],
                cwd=DATA_DIR, control=control, env=env,
                limits=RunLimits(**dict(limits.model_dump(),wall_seconds=max(.001,limits.wall_seconds-(time.monotonic()-job['queued_monotonic'])))),
                cancel=_cancel_events[analysis_id])
            job['supervisor'] = outcome
            if outcome['status'] != 'exited':
                job.update(status=outcome['status'], error=outcome['error'], completed_at=now())
                job['partial_cases'] = preserve_interrupted(DATA_DIR, control, job['status'], job['error'])
                return
            if not result_path.exists():
                raise RuntimeError(f"Worker exited {outcome['returncode']} without result; see job log")
            result = load(result_path)
            if outcome['returncode'] != 0 or result.get('status') != 'completed':
                raise RuntimeError(result.get('error', 'Worker failed'))
            job.update(result, progress=100, completed_at=now(), case_id=result['case_ids'][0])
        except asyncio.CancelledError:
            job.update(status='interrupted', error='API stopped')
            job['partial_cases'] = preserve_interrupted(DATA_DIR, control, job['status'], job['error'])
            raise
        except Exception as exc:
            job.update(status='failed', error=f'{type(exc).__name__}: {exc}', completed_at=now())
            job['partial_cases'] = preserve_interrupted(DATA_DIR, control, job['status'], job['error'])
        finally:
            save(state, job)
            _cancel_events.pop(analysis_id, None)
            analysis_queue.pop(analysis_id, None)

@app.post('/api/analysis/{analysis_id}/cancel')
async def cancel_analysis(analysis_id: str):
    await get_analysis_status(analysis_id)
    job = analysis_queue.get(analysis_id)
    if job is None or job['status'] not in {'queued','running'}:
        return load(JOBS_DIR/(analysis_id+'.json'))
    _cancel_events[analysis_id].set()
    job['cancel_requested_at'] = now()
    if job['status'] == 'queued': job.update(status='cancelled', completed_at=now())
    save(JOBS_DIR/(analysis_id+'.json'), job)
    return job

@app.get('/api/analyses')
async def list_analyses(limit: int = 30):
    if not 1 <= limit <= 100: raise HTTPException(400,'Invalid limit')
    paths = [path for path in JOBS_DIR.glob('analysis_*.json') if path.stem[9:].isalnum()]
    for identifier,_ in controls(DATA_DIR,JOBS_DIR):
        if not (JOBS_DIR/(identifier+'.json')).exists(): await get_analysis_status(identifier)
    paths = [path for path in JOBS_DIR.glob('analysis_*.json') if path.stem[9:].isalnum()]
    paths.sort(key=lambda path:path.stat().st_mtime, reverse=True)
    return {'jobs':[dict(await get_analysis_status(path.stem),analysis_id=path.stem) for path in paths[:limit]], 'total':len(paths)}

@app.get('/api/analysis/{analysis_id}/log')
async def job_log(analysis_id: str):
    await get_analysis_status(analysis_id)
    path = control_path(DATA_DIR,JOBS_DIR,analysis_id)/'worker.log'
    if not path.exists(): return {'text':'Il worker non ha ancora prodotto un log.','truncated':False}
    size = path.stat().st_size
    with path.open('rb') as stream:
        stream.seek(max(0,size-65536))
        text = stream.read(65536).decode('utf-8',errors='replace')
    return {'text':text,'truncated':size>65536}

@app.post('/api/cases/{case_id}/verify')
async def verify_evidence(case_id: str):
    from ..core.verify import verify_case
    directory = case_path(case_id)
    await require_stable_case(directory)
    try: valid = await asyncio.to_thread(verify_case,directory)
    except (OSError,ValueError,TypeError,KeyError): valid = False
    return {'case_id':case_id,'integrity':'verified' if valid else 'failed','checked_at':now(),
        'scope':'Local file consistency; no independent origin or signature is established'}

@app.get('/api/analysis/{analysis_id}')
async def get_analysis_status(analysis_id: str):
    if not analysis_id.startswith('analysis_') or not analysis_id[9:].isalnum():
        raise HTTPException(400, 'Invalid analysis ID')
    path = JOBS_DIR / (analysis_id + '.json')
    async with _recovery_locks.setdefault(analysis_id, asyncio.Lock()):
        try: job = job_state(DATA_DIR,JOBS_DIR,analysis_id)
        except FileNotFoundError: raise HTTPException(404,'Analysis not found')
        control = control_path(DATA_DIR,JOBS_DIR,analysis_id)
        stopped = read_progress(control/'supervisor.json').get('tree_stopped')
        external = job.get('origin') in {'cli','legacy_cli'}
        owner = job.get('supervisor_owner') or read_progress(control/'process.json').get('supervisor_owner',{})
        owner_live = identity_alive(owner) if external else False
        if external and owner_live is False:
            # The CLI may have published completion after the first snapshot and
            # before its owner exited. Once that owner is gone, reload its final
            # acknowledgment before deciding whether recovery is still needed.
            job = job_state(DATA_DIR,JOBS_DIR,analysis_id)
            stopped = read_progress(control/'supervisor.json').get('tree_stopped')
            external = job.get('origin') in {'cli','legacy_cli'}
            owner = job.get('supervisor_owner') or read_progress(control/'process.json').get('supervisor_owner',{})
            owner_live = identity_alive(owner) if external else False
        needs_recovery = (job.get('status') in {'running','recovery_blocked'} or
                          (job.get('status') == 'interrupted' and stopped is not True) or stopped is False)
        if external and job.get('status') in {'running','queued','recovery_blocked'} and (
                owner_live is True or owner_live is None):
            # API must not kill an active CLI or guess ownership for legacy jobs.
            if owner_live is None:
                job.update(status='recovery_blocked',error='CLI supervisor identity cannot be established')
                # Do not overwrite state owned by a possibly live modern CLI.
                # Legacy discovery caches are refreshed from controls below.
        elif analysis_id not in analysis_queue and needs_recovery:
            outcome = await recover_worker(control)
            job['supervisor'] = outcome
            if outcome['tree_stopped']:
                error = outcome.get('error') or 'API restarted after worker shutdown'
                job.update(status='interrupted',error=error,completed_at=now())
                job['partial_cases'] = preserve_interrupted(DATA_DIR,control,'interrupted',error)
            else:
                job.update(status='recovery_blocked',error=outcome['error'])
            save(path,job)
        elif analysis_id not in analysis_queue and job.get('status') == 'queued':
            # run_analysis persists running before launching a worker.
            control.mkdir(parents=True,exist_ok=True)
            from ..core.runtime import atomic_json
            atomic_json(control/'supervisor.json',{'status':'interrupted','tree_stopped':True,
                'error':'API restarted before worker launch'})
            job.update(status='interrupted',error='API restarted before worker launch',completed_at=now())
            save(path,job)
        if not path.exists() or (job.get('origin') == 'legacy_cli' and job != read_progress(path)):
            save(path,job)
    progress = read_progress(control/'progress.json')
    if progress: job['observed_progress'] = progress
    return job

@app.get('/api/cases')
async def list_cases(limit: int = 20, offset: int = 0):
    if not 1 <= limit <= 100 or offset < 0: raise HTTPException(400, 'Invalid pagination')
    paths = sorted(CASES_DIR.glob('*/manifest.json'), key=lambda p:p.stat().st_mtime, reverse=True)
    cases = []
    for path in paths[offset:offset+limit]:
        execution, score = path.parent/'execution.json', path.parent/'report/score.json'
        status = await stable_case_status(path.parent)
        if status in UNSTABLE_CASE_STATUSES:
            cases.append({'case_id':path.parent.name,'status':status,'summary':{},'artifact_errors':{}})
            continue
        errors = {}
        manifest = artifact(path, errors) or {}
        cases.append({'case_id':path.parent.name, 'created_at':manifest.get('created_utc'),
            'subject':str(read_progress(path.parent/'headers.json').get('subject',''))[:200],
            'status':status,
            'summary':(artifact(score, errors) or {}) if score.exists() and status == 'completed' else {},
            'artifact_errors':errors})
    return {'cases':cases, 'total':len(paths), 'limit':limit, 'offset':offset}

@app.get('/api/cases/{case_id}')
async def get_case_detail(case_id: str):
    directory = case_path(case_id)
    result = {'case_id':case_id, 'status':await require_stable_case(directory)}
    headers = read_progress(directory/'headers.json')
    result['email'] = {key:headers.get(key) for key in ('subject','from','to','date')}
    files = {'manifest':'manifest.json','score':'report/score.json','origin':'origin.json',
        'mime':'mime_analysis.json','attachments':'attachments.json','coverage':'analysis_coverage.json','authentication':'auth.json','deobfuscation':'deobfuscation_results.json',
        'attribution_matrix':'attribution_matrix.json','execution':'execution.json',
        'criminal_intelligence':'criminal_intelligence.json','header_inventory':'header_inventory.json',
        'mime_body_evidence':'mime_body_evidence.json','mime_header_inventory':'mime_header_inventory.json'}
    for key, name in files.items():
        if (directory/name).exists():
            result[key] = artifact(directory/name, result.setdefault('artifact_errors', {}))
    if result.get('execution') and result['status'] != 'completed':
        result['execution'] = dict(result['execution'], recorded_status=result['execution'].get('status'), status=result['status'])
    for key, name in {'executive_report':'report/executive.md','technical_report':'report/technical.md'}.items():
        if (directory/name).exists(): result[key] = (directory/name).read_text(encoding='utf-8', errors='replace')
    return result

@app.post('/api/query')
async def query_cases(query: CaseQuery):
    database, matches = CASES_DIR/'index.db', []
    if database.exists():
        with closing(sqlite3.connect(f'{database.as_uri()}?mode=ro', uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            matches = [describe_fingerprint(dict(row)) for row in connection.execute(
                'SELECT c.* FROM cases c JOIN indicators i ON c.id=i.case_id WHERE i.type=? AND i.value=?',
                (query.query_type,query.value))]
    stable_matches = []
    for match in matches:
        identifier = 'case-' + match['id']
        if Path(identifier).name == identifier:
            match['execution_status'] = await stable_case_status(CASES_DIR/identifier)
            if match['execution_status'] in UNSTABLE_CASE_STATUSES: continue
            stable_matches.append(match)
    return {'query_type':query.query_type,'value':query.value,'matches':stable_matches}

@app.get('/api/statistics')
async def get_statistics():
    paths = list(CASES_DIR.glob('*/manifest.json'))
    countries, asns = Counter(), Counter()
    for path in paths:
        if await stable_case_status(path.parent) != 'completed': continue
        origin = path.parent/'origin.json'
        if origin.exists():
            data = read_progress(origin)
            if data.get('cc'): countries[data['cc']] += 1
            if data.get('asn'): asns[str(data['asn'])] += 1
    return {'total_cases':len(paths),'top_countries':countries.most_common(10),
        'top_asns':asns.most_common(10),'operator_attribution':'not established'}

@app.get('/api/export/{case_id}')
async def export_case(case_id: str, format: str = 'zip'):
    if format != 'zip': raise HTTPException(400, 'Only ZIP export supported')
    directory = case_path(case_id)
    await require_stable_case(directory)
    from ..core.evidence import file_inventory
    try: await asyncio.to_thread(file_inventory,directory)
    except ValueError as exc: raise HTTPException(409,str(exc)) from exc
    archive = await asyncio.to_thread(shutil.make_archive,
        str(EXPORT_DIR/(case_id+'-'+uuid.uuid4().hex)), 'zip', str(directory))
    return FileResponse(archive, filename=case_id+'.zip', media_type='application/zip')

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
