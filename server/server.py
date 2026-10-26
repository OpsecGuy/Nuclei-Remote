#!/usr/bin/env python3
"""Single-user Nuclei controller with authenticated public HTTP/HTTPS API."""
import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
import hmac
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

PROFILES = {'cve': ['-tags', 'cve'], 'serious': ['-tags', 'cve', '-severity', 'high,critical'], 'web': []}
ID = re.compile(r'^[a-f0-9]{32}$')
LOGGER = logging.getLogger('nuclei_remote')


class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {'time': self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z'),
                'level': record.levelname, 'event': record.getMessage()}
        data.update(getattr(record, 'fields', {}))
        if record.exc_info:
            data['exception'] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def event(name, level=logging.INFO, **fields):
    LOGGER.log(level, name, extra={'fields': fields})


def configure_logging(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    LOGGER.handlers.clear()
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    for handler in (logging.StreamHandler(), RotatingFileHandler(directory / 'server.log', maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')):
        handler.setFormatter(JsonFormatter())
        LOGGER.addHandler(handler)


class WindowLimit:
    """Bounded fixed-window IP buckets; no tokens or request bodies retained."""
    def __init__(self, count, seconds=60):
        self.count, self.seconds, self.buckets = count, seconds, OrderedDict()

    def allow(self, key):
        now = time.monotonic()
        start, count = self.buckets.get(key, (now, 0))
        if now - start >= self.seconds:
            start, count = now, 0
        self.buckets[key] = (start, count + 1)
        self.buckets.move_to_end(key)
        if len(self.buckets) > 4096:
            self.buckets.popitem(last=False)
        return count < self.count

    def blocked(self, key):
        start, count = self.buckets.get(key, (0, 0))
        return time.monotonic() - start < self.seconds and count >= self.count


def normalize_host(value):
    return value.rstrip('.').encode('idna').decode('ascii').lower()


class Controller:
    def __init__(self, root, token, binary, timeout=1800):
        if len(token) < 32:
            raise ValueError('NUCLEI_API_TOKEN must contain at least 32 characters.')
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.token = token
        self.binary, self.timeout = binary, timeout
        self.lock = threading.RLock()
        self.jobs, self.processes, self.stops, self.workers = {}, {}, {}, {}
        for path in self.root.glob('*/job.json'):
            if not ID.fullmatch(path.parent.name):
                continue
            job = json.loads(path.read_text(encoding='utf-8'))
            if job['status'] == 'running':
                job.update(status='interrupted', error='The service was restarted.')
                event('job_recovered', job_id=path.parent.name, status='interrupted')
            self.jobs[path.parent.name] = job
            self.persist(job)

    def persist(self, job):
        path = self.root / job['id'] / 'job.json'
        temp = path.with_suffix('.tmp')
        temp.write_text(json.dumps(job, ensure_ascii=False), encoding='utf-8')
        temp.replace(path)

    def validate_target(self, target):
        if not isinstance(target, str) or len(target) > 2048 or any(ord(c) < 33 for c in target):
            raise ValueError('Invalid target URL.')
        url = urlsplit(target)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username is not None or url.password is not None or url.fragment:
            raise ValueError('An HTTP/HTTPS URL without credentials or a # fragment is required.')
        try:
            port = url.port
        except ValueError:
            raise ValueError('Target port must be an integer from 1 to 65535.') from None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError('Target port must be an integer from 1 to 65535.')
        host = normalize_host(url.hostname)
        try:
            addresses = socket.getaddrinfo(host, port if port is not None else (443 if url.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise ValueError('Unable to resolve the target hostname.') from error
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise ValueError('The target must resolve to public IP addresses; local and private addresses are blocked.')
        return target

    def start(self, target, profile, rate_limit=5):
        if type(rate_limit) is not int or not 0 <= rate_limit <= 2147483647:
            raise ValueError('rate_limit must be an integer from 0 to 2147483647; 0 = unlimited.')
        if not isinstance(profile, str) or profile not in PROFILES:
            raise ValueError('Unknown scan profile.')
        target = self.validate_target(target)
        with self.lock:
            if any(job['status'] == 'running' for job in self.jobs.values()):
                raise RuntimeError('Another scan is already running. Wait for it to finish or stop it.')
            jid = uuid.uuid4().hex
            directory = self.root / jid
            directory.mkdir(mode=0o700)
            output = directory / 'results.txt'
            output.touch(mode=0o600)
            job = dict(id=jid, target=target, profile=profile, rate_limit=rate_limit, status='running', created_at=int(time.time()), output_file=str(output), error=None)
            self.jobs[jid] = job
            self.stops[jid] = threading.Event()
            self.persist(job)
            event('job_created', job_id=jid, profile=profile, rate_limit=rate_limit, target_host=urlsplit(target).hostname, output_file=str(output))
            worker = threading.Thread(target=self.run, args=(jid,), daemon=True)
            self.workers[jid] = worker
            worker.start()
            return dict(job)

    def command(self, job):
        return [self.binary, '-u', job['target'], '-pt', 'http', *PROFILES[job['profile']],
                '-rl', str(job.get('rate_limit', 5)), '-c', '2', '-bs', '1', '-dr', '-ni', '-duc', '-nc',
                '-stats', '-si', '10',
                '-o', job['output_file']]

    def kill(self, process):
        if process.poll() is None:
            try:
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass

    def run(self, jid):
        job = self.jobs[jid]
        process = None
        status, error = 'failed', None
        try:
            if self.stops[jid].is_set():
                status = 'cancelled'
                return
            with (self.root / jid / 'nuclei.log').open('wb') as log:
                process = subprocess.Popen(self.command(job), stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT, shell=False, start_new_session=True)
                with self.lock:
                    self.processes[jid] = process
                event('nuclei_started', job_id=jid, pid=process.pid, profile=job['profile'], rate_limit=job.get('rate_limit', 5))
                deadline = time.monotonic() + self.timeout
                next_progress = time.monotonic() + 30
                while True:
                    if self.stops[jid].is_set():
                        status = 'cancelled'
                        break
                    if time.monotonic() >= deadline:
                        status, error = 'timeout', 'Time limit: 30 minutes.'
                        break
                    if sum(p.stat().st_size for p in (self.root / jid).iterdir() if p.is_file()) > 25 * 1024 * 1024:
                        status, error = 'limit', 'Scan file size limit: 25 MiB.'
                        break
                    code = process.poll()
                    if code is not None:
                        status = 'done' if code == 0 else 'failed'
                        error = None if code == 0 else f'Nuclei exited with code {code}. Check nuclei.log on the server.'
                        break
                    if time.monotonic() >= next_progress:
                        event('job_progress', job_id=jid, result_bytes=Path(job['output_file']).stat().st_size)
                        next_progress = time.monotonic() + 30
                    self.stops[jid].wait(0.5)
        except Exception as exc:
            error = f'Unable to run the scan: {exc}'
            LOGGER.exception('nuclei_error', extra={'fields':{'job_id':jid}})
        finally:
            if process is not None:
                self.kill(process)
                process.wait()
            with self.lock:
                job.update(status=status, error=error, finished_at=int(time.time()))
                self.processes.pop(jid, None)
                self.stops.pop(jid, None)
                self.persist(job)
                event('job_finished', job_id=jid, status=status, exit_code=process.poll() if process else None,
                      duration_seconds=int(time.time())-job['created_at'], result_bytes=Path(job['output_file']).stat().st_size)
                self.workers.pop(jid, None)

    def cancel(self, jid):
        with self.lock:
            job = self.jobs[jid]
            if jid in self.stops:
                self.stops[jid].set()
                event('job_cancel_requested', job_id=jid)
            return dict(job)

    def shutdown(self):
        with self.lock:
            for event in self.stops.values():
                event.set()
            for process in self.processes.values():
                self.kill(process)
            workers = list(self.workers.values())
        for worker in workers:
            worker.join(timeout=5)


def create_app(controller):
    @asynccontextmanager
    async def lifespan(app):
        event('api_ready', results_dir=str(controller.root))
        yield
        event('api_stopping')
        await asyncio.to_thread(controller.shutdown)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    request_limit, failures = WindowLimit(180), WindowLimit(10)

    def error(status, text):
        return JSONResponse({'error':text}, status_code=status)

    @app.middleware('http')
    async def security(request: Request, call_next):
        started = time.monotonic()
        request_id = uuid.uuid4().hex[:16]
        ip = request.client.host if request.client else 'unknown'
        # Log only known route shapes; never raw paths, queries or headers.
        path = request.url.path
        parts = path.strip('/').split('/')
        job_id = parts[2] if len(parts) in (3,4) and parts[:2] == ['api','jobs'] and ID.fullmatch(parts[2]) else None
        route = path if path in ('/api/health','/api/jobs') else '/api/jobs/:id'
        if job_id and len(parts) == 4 and parts[3] in ('cancel','output','log'):
            route += '/' + parts[3]
        elif not job_id and path not in ('/api/health','/api/jobs'):
            route = 'unknown'
        response = None
        try:
            if not request_limit.allow(ip) or failures.blocked(ip):
                response = error(429, 'Request or authentication attempt limit reached. Wait one minute.')
                response.headers['Retry-After'] = '60'
                event('rate_limited', level=logging.WARNING, ip=ip, request_id=request_id)
            else:
                credential = request.headers.get('authorization','').encode('utf-8')
                if not hmac.compare_digest(credential, ('Bearer '+controller.token).encode('utf-8')):
                    failures.allow(ip)
                    event('auth_failed', level=logging.WARNING, ip=ip, request_id=request_id)
                    response = error(401, 'Invalid API key.')
                    response.headers['WWW-Authenticate'] = 'Bearer'
                elif request.method == 'POST':
                    try:
                        size = int(request.headers.get('content-length','0'))
                    except ValueError:
                        size = 0
                    if not 0 < size <= 4096 or 'transfer-encoding' in request.headers:
                        response = error(413, 'A JSON body with Content-Length is required, up to 4096 bytes.')
                    elif request.headers.get('content-type','').split(';')[0].strip().lower() != 'application/json':
                        response = error(415, 'Content-Type: application/json is required.')
                if response is None:
                    response = await call_next(request)
        except Exception:
            LOGGER.exception('api_error', extra={'fields':{'request_id':request_id}})
            response = error(500, 'Server error. Check server.log; request ID: '+request_id)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Request-ID'] = request_id
        event('http_request', ip=ip, request_id=request_id, method=request.method[:12], route=route,
              job_id=job_id, status=response.status_code, duration_ms=round((time.monotonic()-started)*1000))
        return response

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        event('request_rejected', level=logging.WARNING, reason='validation')
        return error(400, str(exc))

    @app.exception_handler(RuntimeError)
    async def conflict(request, exc):
        return error(409, str(exc))

    @app.exception_handler(OSError)
    async def disk_error(request, exc):
        LOGGER.exception('storage_error')
        return error(500, 'Server storage error. Check server.log.')

    def job_snapshot(jid):
        if not ID.fullmatch(jid):
            return None
        with controller.lock:
            job = controller.jobs.get(jid)
            return dict(job) if job else None

    async def read_json(request):
        async def collect():
            chunks, total = [], 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > 4096:
                    raise ValueError('JSON body is too large.')
                chunks.append(chunk)
            return b''.join(chunks)
        try:
            raw = await asyncio.wait_for(collect(), timeout=10)
        except asyncio.TimeoutError:
            raise ValueError('Request body read timeout.')
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError('A JSON object is required.')
        return body

    @app.get('/api/health')
    def health():
        return {'ok':True, 'version':'1.3.1'}

    @app.get('/api/jobs')
    def jobs():
        with controller.lock:
            recent = sorted(controller.jobs.values(), key=lambda item:item['created_at'], reverse=True)[:20]
            return {'jobs':[dict(job) for job in recent]}

    @app.post('/api/jobs', status_code=202)
    async def start_job(request: Request):
        body = await read_json(request)
        if set(body) - {'target','profile','rate_limit'}:
            raise ValueError('Allowed fields: target, profile, and rate_limit.')
        return await asyncio.to_thread(controller.start, body.get('target'), body.get('profile','cve'), body.get('rate_limit',5))

    @app.get('/api/jobs/{jid}')
    def status(jid: str):
        return job_snapshot(jid) or error(404, 'Scan not found.')

    @app.post('/api/jobs/{jid}/cancel')
    async def cancel_job(jid: str, request: Request):
        await read_json(request)
        if not job_snapshot(jid):
            return error(404, 'Scan not found.')
        return controller.cancel(jid)

    @app.get('/api/jobs/{jid}/output')
    def output(jid: str):
        job = job_snapshot(jid)
        if not job:
            return error(404, 'Scan not found.')
        if job['status'] == 'running':
            return error(409, 'Wait for the scan to finish.')
        with (controller.root / jid / 'results.txt').open('r',encoding='utf-8',errors='replace') as file:
            text = file.read(26*1024*1024)
        event('output_downloaded', job_id=jid, bytes=len(text.encode('utf-8')))
        return PlainTextResponse(text)

    @app.get('/api/jobs/{jid}/log')
    def scan_log(jid: str):
        if not job_snapshot(jid):
            return error(404, 'Scan not found.')
        path = controller.root / jid / 'nuclei.log'
        if not path.exists():
            return PlainTextResponse('Waiting for Nuclei to start…')
        with path.open('rb') as file:
            file.seek(max(0, path.stat().st_size-65536))
            text = file.read(65536).decode('utf-8',errors='replace')
        return PlainTextResponse(text)

    return app


def main():
    os.umask(0o077)
    configure_logging(os.environ.get('NUCLEI_LOG_DIR','./logs'))
    binary = shutil.which(os.environ.get('NUCLEI_BIN','nuclei'))
    if not binary:
        raise SystemExit('Nuclei was not found. Set NUCLEI_BIN to its full executable path.')
    controller = Controller(os.environ.get('NUCLEI_RESULTS_DIR','./results'), os.environ.get('NUCLEI_API_TOKEN',''), binary)
    host, port = os.environ.get('NUCLEI_API_HOST','0.0.0.0'), int(os.environ.get('NUCLEI_API_PORT','8765'))
    cert, key = os.environ.get('NUCLEI_TLS_CERT') or None, os.environ.get('NUCLEI_TLS_KEY') or None
    if bool(cert) != bool(key):
        raise SystemExit('Set both NUCLEI_TLS_CERT and NUCLEI_TLS_KEY.')
    event('server_starting', bind=host, port=port, tls=bool(cert), binary=binary)
    if not cert and host != '127.0.0.1':
        event('plaintext_http', level=logging.WARNING, detail='HTTP does not encrypt the API key. HTTPS is recommended.')
    uvicorn.run(create_app(controller), host=host, port=port, workers=1, access_log=False,
                proxy_headers=False, server_header=False, limit_concurrency=32, backlog=64,
                timeout_keep_alive=5, timeout_graceful_shutdown=15, h11_max_incomplete_event_size=16384,
                ssl_certfile=cert, ssl_keyfile=key)


if __name__ == '__main__':
    main()
