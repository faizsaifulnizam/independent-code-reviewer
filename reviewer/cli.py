"""Trusted controller; models receive only approved inert text, never this process API."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from urllib.parse import quote
import uuid

from .state import claim, save_atomic


REPO = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z')


def run_process(argv, deadline, max_bytes):
    """Closed stdin, finite aggregate output, finite lifetime, no shell or retry."""
    env = {k: v for k, v in os.environ.items() if k.upper() in {
        'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'HOME', 'USERPROFILE',
        'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR', 'GH_TOKEN', 'GITHUB_TOKEN',
        'GH_CONFIG_DIR', 'PYTHONIOENCODING'}}
    env['PYTHONIOENCODING'] = 'utf-8'
    env['GH_PROMPT_DISABLED'] = '1'
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    mutex = threading.Lock()
    total = 0

    def drain(pipe, index):
        nonlocal total
        while chunk := pipe.read(4096):
            with mutex:
                room = max(0, max_bytes - total)
                buffers[index].extend(chunk[:room])
                total += len(chunk)
                if total > max_bytes:
                    overflow.set()

    threads = [threading.Thread(target=drain, args=(pipe, i), daemon=True)
               for i, pipe in enumerate((proc.stdout, proc.stderr))]
    for thread in threads:
        thread.start()
    reason = None
    try:
        while proc.poll() is None:
            if overflow.is_set():
                reason = 'PAYLOAD_LIMIT'
                break
            if time.monotonic() >= deadline:
                reason = 'TIME_BUDGET'
                break
            time.sleep(0.01)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        for thread in threads:
            thread.join(timeout=1)
        proc.stdout.close()
        proc.stderr.close()
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError('CONTROL_UNPROVEN')
    if overflow.is_set():
        raise RuntimeError('PAYLOAD_LIMIT')
    if reason:
        raise RuntimeError(reason)
    if proc.returncode:
        raise RuntimeError('AUTH_FAILED')
    return bytes(buffers[0])


class GitHubClient:
    def __init__(self, repository, deadline):
        if not REPO.fullmatch(repository) or '..' in repository.split('/'):
            raise ValueError('Invalid repository')
        self.repository = repository
        self.deadline = deadline

    def identity(self):
        from .validate import parse_json
        return parse_json(run_process(['gh', 'api', 'user', '--hostname', 'github.com', '--method', 'GET'],
                                      min(self.deadline - 5, time.monotonic() + 30), 131072),
                          max_bytes=131072)

    def get(self, api_path):
        from .validate import parse_json
        prefixes = ('repos/' + self.repository, '/repos/' + self.repository)
        if not any(api_path == prefix or api_path.startswith(prefix + '/') for prefix in prefixes):
            raise RuntimeError('NOT_AUTHORIZED')
        if any(x in api_path for x in ('\\', '\n', '\r', '\x00', '/../', '#')):
            raise ValueError('Invalid API path')
        raw = run_process(['gh', 'api', api_path, '--hostname', 'github.com', '--method', 'GET'],
                          min(self.deadline - 5, time.monotonic() + 30), 2 * 1024 * 1024)
        return parse_json(raw, max_bytes=2 * 1024 * 1024)


class Authority:
    """Fresh remote authority intersected with the immutable original local run scope."""
    def __init__(self, request, client, control_repository, ledger, deadline, *, run_id):
        self.request = dict(request)
        self.client = client
        self.control_repository = control_repository
        self.ledger = Path(ledger)
        self.deadline = deadline
        self.run_id = run_id
        self.lock = threading.Lock()
        self.cancel_path = self.ledger.parent / (run_id + '.cancel')
        self.manifest = None
        grant, receipt = self._current()
        self.original = grant
        self.control_id = receipt['control_repository_id']

    def _current(self):
        from .validate import parse_json
        prefix = 'repos/' + self.control_repository
        repository = self.client.get(prefix)
        if repository.get('private') is not False or repository.get('full_name') != self.control_repository:
            raise RuntimeError('NOT_AUTHORIZED')
        oid = self.client.get(prefix + '/git/ref/heads/' + quote(repository['default_branch'], safe=''))['object']['sha']
        if not re.fullmatch('[0-9a-f]{40}', oid):
            raise RuntimeError('PROTOCOL_INVALID')
        record = self.client.get(prefix + '/contents/config/repositories.json?ref=' + oid)
        if record.get('encoding') != 'base64':
            raise RuntimeError('PROTOCOL_INVALID')
        encoded = record.get('content', '')
        if not isinstance(encoded, str) or len(encoded) > 180000:
            raise RuntimeError('PAYLOAD_LIMIT')
        raw = base64.b64decode(''.join(encoded.split()), validate=True)
        config = parse_json(raw, max_bytes=131072)
        if config.get('schema_version') != '0.2' or type(config.get('version')) is not int:
            raise RuntimeError('PROTOCOL_INVALID')
        grant = config.get('grants', {}).get(self.request['grant_id'])
        if not isinstance(grant, dict):
            raise RuntimeError('NOT_AUTHORIZED')
        return grant, {'control_repository_id': repository['id'], 'control_oid': oid,
                       'grant_version': config['version'], 'observed_at': datetime.now(timezone.utc).isoformat()}

    def _allowed_scope(self, grant):
        request = self.request
        if grant.get('enabled') is not True:
            raise RuntimeError('REVOKED')
        if grant.get('public_only') is not True:
            raise RuntimeError('NOT_AUTHORIZED')
        for key in ('repository_id', 'repository', 'actor_id', 'policy_digest', 'runtime_digest'):
            if grant.get(key) != request.get(key):
                raise RuntimeError('NOT_AUTHORIZED')
        for key, value in (('modes', request['mode']), ('triggers', request['trigger']),
                           ('efforts', request['requested_effort'])):
            if value not in grant.get(key, []):
                raise RuntimeError('NOT_AUTHORIZED')
        if request['subject_number'] not in grant.get('subjects', {}).get(request['subject_kind'], []):
            raise RuntimeError('NOT_AUTHORIZED')
        expiry = datetime.fromisoformat(grant['expires_at'].replace('Z', '+00:00'))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise RuntimeError('REVOKED')
        cap = grant.get('max_responses')
        if type(cap) is not int or not 0 < cap <= 14:
            raise RuntimeError('RESPONSE_BUDGET')

    def bind_manifest(self, manifest):
        self.manifest = manifest

    def __call__(self, action, resource):
        from .validate import canonical_digest
        receipt = {'allowed': False, 'run_id': self.run_id, 'request_id': self.request['request_id'],
                   'action': action, 'reason': 'NOT_AUTHORIZED'}
        try:
            if action not in ('read_evidence', 'model_request') or not isinstance(resource, dict):
                return receipt
            for key in ('request_id', 'repository_id', 'subject_kind', 'subject_number'):
                if resource.get(key) != self.request[key]:
                    return receipt
            if time.monotonic() >= self.deadline - 5:
                raise RuntimeError('TIME_BUDGET')
            if self.cancel_path.exists():
                raise RuntimeError('CANCELLED')
            grant, observed = self._current()
            receipt.update(observed)
            if observed['control_repository_id'] != self.control_id:
                return receipt
            self._allowed_scope(self.original)
            self._allowed_scope(grant)
            if any(grant.get(key) != self.original.get(key) for key in ('context_paths', 'limits')):
                raise RuntimeError('NOT_AUTHORIZED')
            if time.monotonic() >= self.deadline - 5:
                raise RuntimeError('TIME_BUDGET')
            if self.cancel_path.exists():
                raise RuntimeError('CANCELLED')
            if action == 'read_evidence' and 'evidence_id' in resource:
                if self.manifest is None:
                    return receipt
                entry = next((e for e in self.manifest['entries']
                              if e['evidence_id'] == resource['evidence_id']), None)
                if entry is None or resource.get('digest') != entry['blob_digest']:
                    return receipt
                start, end = resource.get('start_line'), resource.get('end_line')
                if (entry['disposition'] != 'required' or type(start) is not int or type(end) is not int
                        or not 1 <= start <= end <= entry['line_count']):
                    return receipt
            if action == 'model_request':
                if grant.get('use_balance_off') is not True or self.original.get('use_balance_off') is not True:
                    raise RuntimeError('CONTROL_UNPROVEN')
                for current in (self.original, grant):
                    if current.get('provider') != 'opencode-go' or current.get('model') != 'deepseek-v4.1-flash':
                        return receipt
                for key, value in {'run_id': self.run_id, 'provider': 'opencode-go',
                                   'model': 'deepseek-v4.1-flash', 'effort': self.request['requested_effort'],
                                   'policy_digest': self.request['policy_digest'],
                                   'runtime_digest': self.request['runtime_digest']}.items():
                    if resource.get(key) != value:
                        return receipt
                slot = resource.get('slot')
                attempt_id = resource.get('attempt_id')
                if slot not in ('finder', 'J1', 'J2', 'J3') or not isinstance(attempt_id, str) or not attempt_id:
                    return receipt
                if self.manifest is not None and resource.get('evidence_digest') != self.manifest['evidence_digest']:
                    return receipt
                with self.lock:
                    if time.monotonic() >= self.deadline - 5 or self.cancel_path.exists():
                        raise RuntimeError('CANCELLED')
                    ledger = _read_record(self.ledger) if self.ledger.exists() else {
                        'grant_id': self.request['grant_id'], 'policy_digest': self.request['policy_digest'],
                        'runtime_digest': self.request['runtime_digest'], 'attempts': []}
                    for key in ('grant_id', 'policy_digest', 'runtime_digest'):
                        if ledger.get(key) != self.request[key]:
                            return receipt
                    attempts = ledger['attempts']
                    ours = [a for a in attempts if a['run_id'] == self.run_id]
                    cap = min(self.original['max_responses'], grant['max_responses'])
                    if len(attempts) >= cap or len(ours) >= 7:
                        raise RuntimeError('RESPONSE_BUDGET')
                    if any(a['attempt_id'] == attempt_id for a in attempts):
                        raise RuntimeError('RESPONSE_BUDGET')
                    if sum(a['slot'] == slot for a in ours) >= (4 if slot == 'finder' else 1):
                        raise RuntimeError('RESPONSE_BUDGET')
                    reservation = {'run_id': self.run_id, 'attempt_id': attempt_id, 'slot': slot,
                                   'resource_digest': canonical_digest(resource), 'state': 'admitted_possible_send'}
                    attempts.append(reservation)
                    save_atomic(self.ledger, ledger)
                    receipt['attempt_id'] = attempt_id
            receipt.update({'allowed': True, 'reason': None})
        except RuntimeError as error:
            receipt['reason'] = str(error) if re.fullmatch('[A-Z_]+', str(error)) else 'NOT_AUTHORIZED'
        except (ValueError, KeyError, TypeError, OSError):
            receipt['reason'] = 'NOT_AUTHORIZED'
        return receipt


def _read_record(path, maximum=131072):
    from .validate import parse_json
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    return parse_json(data, max_bytes=maximum)


def execute_draft(request, args):
    import hashlib
    root = Path(__file__).resolve().parents[1]
    started = time.monotonic()
    policy_bytes = (root / 'config/review-policy.md').read_bytes()
    runtime_bytes = (root / 'config/runtime.json').read_bytes()
    if hashlib.sha256(policy_bytes).hexdigest() != request['policy_digest']:
        raise ValueError('Policy identity changed')
    if hashlib.sha256(runtime_bytes).hexdigest() != request['runtime_digest']:
        raise ValueError('Runtime identity changed')
    from .validate import parse_json
    runtime = parse_json(runtime_bytes, max_bytes=131072)
    wall = runtime.get('wall_time_s')
    reserve = runtime.get('cleanup_reserve')
    if (type(wall) is not int or type(reserve) is not int
            or not 5 <= reserve < wall <= 900):
        raise ValueError('Invalid runtime wall time or cleanup reserve')
    deadline = started + wall
    if time.monotonic() >= deadline - reserve:
        raise RuntimeError('TIME_BUDGET')
    if args.control_repository != request['repository']:
        raise RuntimeError('NOT_AUTHORIZED')
    client = GitHubClient(request['repository'], deadline)
    if client.identity().get('id') != request['actor_id']:
        raise RuntimeError('NOT_AUTHORIZED')
    run_id = str(uuid.uuid4())
    authority = Authority(request, client, args.control_repository, args.ledger, deadline, run_id=run_id)
    authority._allowed_scope(authority.original)
    from .collect import collect
    from .runner import review
    from .validate import parse_json, validate, render_markdown
    if runtime.get('provider') != 'opencode-go' or runtime.get('model') != 'deepseek-v4.1-flash':
        raise RuntimeError('MODEL_UNAVAILABLE')
    if request['requested_effort'] != runtime.get('effort'):
        raise RuntimeError('NOT_AUTHORIZED')
    budget = {key: runtime[key] for key in ('cleanup_reserve', 'max_responses', 'max_input_bytes',
              'max_response_bytes', 'max_output_tokens', 'network_timeout')}
    budget['deadline'] = deadline
    limits = {'changed_paths': 100, 'total_bytes': 5242880, 'file_bytes': 262144,
              'thread_bytes': 1048576, 'comments': 1000, 'context_paths': runtime['context_paths']}
    runtime.update({key: request[key] for key in ('request_id', 'repository_id', 'subject_kind',
                   'subject_number', 'policy_digest', 'runtime_digest')})
    runtime['run_id'] = run_id
    lock_path = args.ledger.with_name(args.ledger.name + '.lock')
    claim(lock_path, {'run_id': run_id, 'request_id': request['request_id']})
    try:
        if args.output.exists():
            raise ValueError('Output must be a new directory')
        manifest = collect(request, authority.original, client, limits, admit=authority)
        authority.bind_manifest(manifest)
        result = review(manifest, policy_bytes.decode('utf-8'), runtime, budget, admit=authority)
        live = {'currentness': 'unknown', 'authorized': True}
        try:
            fresh = collect(request, authority.original, client, limits, admit=authority)
            snapshot_keys = ('base_oid', 'head_oid', 'repository_oid', 'thread_digest')
            same_snapshot = all(manifest.get(key) == fresh.get(key) for key in snapshot_keys)
            same_entries = [(e['evidence_id'], e['blob_digest'], e['disposition']) for e in manifest['entries']] == [
                (e['evidence_id'], e['blob_digest'], e['disposition']) for e in fresh['entries']]
            live['currentness'] = 'current' if same_snapshot and same_entries else 'stale'
        except RuntimeError as error:
            if str(error) in ('NOT_AUTHORIZED', 'REVOKED', 'CANCELLED'):
                live.update(authorized=False, reason=str(error))
        artifact = validate(request, manifest, result, live)
        if time.monotonic() >= deadline - 5:
            raise RuntimeError('TIME_BUDGET')
        markdown = render_markdown(artifact)
        args.output.mkdir(parents=True, exist_ok=False)
        artifact_digest = save_atomic(args.output / 'review.json', artifact)
        (args.output / 'review.md').write_text(markdown, encoding='utf-8')
        receipts = {r['attempt_id']: r for r in result['execution']['response_receipts']}
        ledger = _read_record(args.ledger)
        for attempt in ledger['attempts']:
            receipt = receipts.get(attempt['attempt_id'])
            if receipt:
                attempt['state'] = receipt['status']
        save_atomic(args.ledger, ledger)
        print(json.dumps({'outcome': artifact['outcome'], 'run_id': run_id,
                          'actual_response_count': result['execution']['actual_response_count'],
                          'artifact_sha256': artifact_digest}))
        return 0 if artifact['outcome'] in ('completed_with_findings', 'completed_with_none') else 4
    finally:
        lock_path.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Independent advisory GitHub PR and issue drafts.')
    commands = parser.add_subparsers(dest='command', required=True)
    draft = commands.add_parser('draft', help='Produce a local draft; cannot post to GitHub.')
    draft.add_argument('--request', required=True, type=Path)
    draft.add_argument('--output', required=True, type=Path)
    draft.add_argument('--control-repository', required=True)
    draft.add_argument('--ledger', type=Path, default=Path('runs/feasibility-ledger.json'))
    args = parser.parse_args(argv)
    try:
        from .validate import check_request
        request = check_request(_read_record(args.request))
        if not REPO.fullmatch(args.control_repository):
            raise ValueError('Invalid control repository')
        return execute_draft(request, args)
    except (ValueError, OSError):
        print('Invalid request, configuration or output destination.', file=sys.stderr)
        return 2
    except RuntimeError as error:
        reason = str(error)
        safe = reason if re.fullmatch(r'[A-Z_]{1,50}', reason) else 'PROTOCOL_INVALID'
        print(json.dumps({'outcome': 'blocked' if safe in {
            'NOT_AUTHORIZED', 'AUTH_FAILED', 'QUOTA_EXHAUSTED', 'MODEL_UNAVAILABLE',
            'CONTROL_UNPROVEN', 'TIME_BUDGET', 'RESPONSE_BUDGET', 'REVOKED', 'CANCELLED',
            'MISSING_EVIDENCE', 'PAYLOAD_LIMIT'} else 'failed', 'reason': safe}), file=sys.stderr)
        return 3 if safe in {'NOT_AUTHORIZED', 'AUTH_FAILED', 'QUOTA_EXHAUSTED',
                            'MODEL_UNAVAILABLE', 'CONTROL_UNPROVEN', 'TIME_BUDGET',
                            'RESPONSE_BUDGET', 'REVOKED', 'CANCELLED', 'MISSING_EVIDENCE',
                            'PAYLOAD_LIMIT'} else 5


if __name__ == '__main__':
    raise SystemExit(main())
