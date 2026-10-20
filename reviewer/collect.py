"""In-memory GitHub evidence snapshots. Source text is untrusted and never executed."""
import base64
import hashlib
import re
from urllib.parse import quote
from reviewer.validate import canonical_digest, check_request


def _oid(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise RuntimeError('PROTOCOL_INVALID')
    return value



def collect(request, grant, source_client, limits, *, admit):
    """Collect only admitted public evidence; malformed GitHub data fails closed."""
    try:
        return _collect(request, grant, source_client, limits, admit=admit)
    except (KeyError, TypeError, AttributeError, UnicodeError):
        raise RuntimeError('PROTOCOL_INVALID') from None


def _collect(request, grant, source_client, limits, *, admit):
    check_request(request)
    caps = dict(changed_paths=100, total_bytes=5242880, file_bytes=262144, thread_bytes=1048576, comments=1000)
    if not isinstance(grant, dict) or not isinstance(limits, dict):
        raise ValueError('invalid collection scope')
    for key, maximum in caps.items():
        value = limits.get(key, maximum)
        allowed = grant.get('limits', {}).get(key, maximum)
        if type(value) is not int or type(allowed) is not int or not 0 <= value <= maximum or not 0 <= allowed <= maximum:
            raise ValueError('invalid collection limit')
        caps[key] = min(value, allowed)
    total = thread_bytes = comment_count = 0
    def source_path(path):
        if (not isinstance(path, str) or len(path) > 4096 or not path
                or any(part in ('', '.', '..') for part in path.split('/'))
                or any(ord(c) < 32 or ord(c) == 127 or c in '\\\\:%?#' for c in path)):
            raise ValueError('invalid source path')
        return path
    contexts = limits.get('context_paths', [])
    approved = grant.get('context_paths', [])
    if not isinstance(contexts, list) or not isinstance(approved, list):
        raise ValueError('invalid context scope')
    for path in contexts + approved:
        source_path(path)
    if (grant.get('repository_id') != request['repository_id'] or grant.get('repository') != request['repository']
            or grant.get('public_only') is not True or not set(contexts) <= set(approved)):
        raise RuntimeError('NOT_AUTHORIZED')
    if len(contexts) > caps['changed_paths']:
        raise RuntimeError('PAYLOAD_LIMIT')
    if len(set(contexts)) != len(contexts):
        raise ValueError('duplicate context path')
    root = '/repos/' + request['repository']
    identity = {k: request[k] for k in ('request_id', 'repository_id', 'subject_kind', 'subject_number')}
    receipts = []

    def get(api_path, **target):
        resource = dict(identity, api_path=api_path, **target)
        decision = admit('read_evidence', resource)
        if not isinstance(decision, dict) or decision.get('allowed') is not True:
            raise RuntimeError(decision.get('reason', 'NOT_AUTHORIZED') if isinstance(decision, dict) else 'NOT_AUTHORIZED')
        result = source_client.get(api_path)
        receipts.append(dict(resource=resource, admission=decision))
        return result

    repo = get(root)
    if (repo.get('id') != request['repository_id'] or type(repo.get('id')) is not int
            or repo.get('full_name') != request['repository']
            or ('owner' in repo and repo['owner'].get('login') != request['repository'].split('/')[0])
            or repo.get('private') is not False or repo.get('visibility', 'public') != 'public'):
        raise RuntimeError('NOT_AUTHORIZED')
    is_pr = request['subject_kind'] == 'pull_request'
    subject_path = root + ('/pulls/' if is_pr else '/issues/') + str(request['subject_number'])
    subject = get(subject_path)
    if type(subject.get('number')) is not int or subject['number'] != request['subject_number']:
        raise RuntimeError('NOT_AUTHORIZED')
    if is_pr:
        for side in ('base', 'head'):
            side_repo = subject[side]['repo']
            if (side_repo.get('id') != request['repository_id'] or side_repo.get('full_name') != request['repository']
                    or side_repo.get('private') is not False):
                raise RuntimeError('NOT_AUTHORIZED')
        revisions = dict(base_oid=_oid(subject['base']['sha']), head_oid=_oid(subject['head']['sha']))
    else:
        if 'pull_request' in subject or subject.get('repository_url') != 'https://api.github.com' + root:
            raise RuntimeError('NOT_AUTHORIZED')
        revisions = dict(repository_oid=_oid(get(root + '/commits/' + quote(repo['default_branch'], safe=''))['sha']))
    entries = []

    def export(text, kind, provenance, *, disposition='required', reason='', **location):
        # ponytail: conservative pattern denylist, not a complete secret scanner.
        if re.search(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})|(?i:(?:api[_-]?key|secret|password|token)\s*[=:]\s*[\"\x27]?[A-Za-z0-9_+/=-]{16,})', text):
            text, disposition, reason = '', 'withheld', 'SECRET_LIKE_CONTENT'
        raw = text.encode('utf-8')
        entries.append(dict(evidence_id=f'E{len(entries)+1:03d}', kind=kind, **location,
                            blob_digest=hashlib.sha256(raw).hexdigest(), text=text, byte_count=len(raw),
                            line_count=len(text.splitlines()), provenance=provenance, disposition=disposition, reason=reason))

    object_ids = set()
    def entry(obj, kind):
        nonlocal total, thread_bytes
        if (not isinstance(obj, dict) or type(obj.get('id')) is not int or obj['id'] <= 0
                or obj.get('body') is not None and not isinstance(obj.get('body'), str)):
            raise RuntimeError('PROTOCOL_INVALID')
        object_key = (kind, obj['id'])
        if object_key in object_ids:
            raise RuntimeError('PROTOCOL_INVALID')
        object_ids.add(object_key)
        for key, target in [('issue_url', root+'/issues/'+str(request['subject_number'])), ('pull_request_url', root+'/pulls/'+str(request['subject_number']))]:
            if key in obj and obj[key] != 'https://api.github.com'+target:
                raise RuntimeError('NOT_AUTHORIZED')
        text = obj['body'] or ''
        raw = text.encode('utf-8')
        total += len(raw)
        thread_bytes += len(raw)
        if total > caps['total_bytes'] or thread_bytes > caps['thread_bytes']:
            raise RuntimeError('PAYLOAD_LIMIT')
        export(text, kind, 'author_claim', issue_object_id=obj['id'], updated_at=obj.get('updated_at', obj.get('submitted_at')))

    pages = 0
    def paginate(path, *, files=False, expected=None):
        nonlocal pages, comment_count
        maximum = caps['changed_paths'] if files else caps['comments']-comment_count
        if expected is not None and (type(expected) is not int or expected < 0):
            raise RuntimeError('PROTOCOL_INVALID')
        if expected is not None and expected > maximum:
            raise RuntimeError('PAYLOAD_LIMIT')
        result = []
        page = 1
        while True:
            batch = get(path + f'?per_page=100&page={page}', page=page)
            pages += 1
            if not isinstance(batch, list) or len(batch) > 100:
                raise RuntimeError('PROTOCOL_INVALID')
            result.extend(batch)
            if len(result) > maximum:
                raise RuntimeError('PAYLOAD_LIMIT')
            if len(batch) < 100:
                if expected is not None and len(result) != expected:
                    raise RuntimeError('MISSING_EVIDENCE')
                if not files:
                    comment_count += len(result)
                return result
            page += 1

    entry(subject, 'issue_body')
    for obj in paginate(root + f'/issues/{request["subject_number"]}/comments', expected=subject.get('comments')):
        entry(obj, 'issue_comment')
    if is_pr:
        for endpoint in ('comments', 'reviews'):
            for obj in paginate(subject_path + '/' + endpoint, expected=subject.get('review_comments') if endpoint == 'comments' else None):
                entry(obj, 'issue_comment')
    thread_entries = entries[:]
    def source(path, revision, kind):
        nonlocal total
        source_path(path)
        location = dict(path=path, revision=revision)
        if any(re.search(r'(?i)^(?:\.env(?:\..*)?|credentials(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|keystore))$', part) for part in path.split('/')):
            export('', kind, 'source', **location, disposition='withheld', reason='SECRET_PATH')
            return
        commit = get(root+'/git/commits/'+revision, revision=revision)
        if commit.get('sha') != revision:
            raise RuntimeError('PROTOCOL_INVALID')
        tree_oid = _oid(commit['tree']['sha'])
        for index, component in enumerate(path.split('/')):
            tree = get(root+'/git/trees/'+tree_oid, revision=revision, path=path)
            if tree.get('truncated') is not False or tree.get('sha') != tree_oid:
                raise RuntimeError('MISSING_EVIDENCE')
            matching = [item for item in tree['tree'] if item['path'] == component]
            if len(matching) != 1:
                raise RuntimeError('MISSING_EVIDENCE')
            item = matching[0]
            if item.get('mode') in ('120000', '160000'):
                export('', kind, 'source', **location, source_oid=_oid(item['sha']), disposition='excluded', reason='SYMLINK' if item['mode']=='120000' else 'SUBMODULE')
                return
            if index < len(path.split('/'))-1:
                if item.get('mode') != '040000' or item.get('type') != 'tree':
                    raise RuntimeError('MISSING_EVIDENCE')
                tree_oid = _oid(item['sha'])
        if item.get('mode') not in ('100644', '100755') or item.get('type') != 'blob':
            raise RuntimeError('MISSING_EVIDENCE')
        if item['size'] > caps['file_bytes'] or total + item['size'] > caps['total_bytes']:
            raise RuntimeError('PAYLOAD_LIMIT')
        data = get(root+'/git/blobs/'+_oid(item['sha']), revision=revision, path=path)
        if data.get('encoding') != 'base64':
            raise RuntimeError('PROTOCOL_INVALID')
        try:
            raw = base64.b64decode(''.join(data['content'].split()), validate=True)
        except (ValueError, TypeError):
            raise RuntimeError('PROTOCOL_INVALID') from None
        total += len(raw)
        if len(raw) > caps['file_bytes'] or total > caps['total_bytes']:
            raise RuntimeError('PAYLOAD_LIMIT')
        actual_oid = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if data.get('sha') != item['sha'] or actual_oid != item['sha']:
            raise RuntimeError('PROTOCOL_INVALID')
        location['source_oid'] = item['sha']
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            text = None
        if text is None or any(ord(c)<32 and c not in '\n\r\t' for c in text):
            export('', kind, 'source', **location, disposition='excluded', reason='BINARY')
        elif text.startswith('version https://git-lfs.github.com/spec/v1'):
            export('', kind, 'source', **location, disposition='excluded', reason='LFS_POINTER')
        else:
            export(text, kind, 'source', **location)

    if is_pr:
        files = paginate(subject_path + '/files', files=True, expected=subject.get('changed_files'))
        if len(files) != subject.get('changed_files') or len({f['filename'] for f in files}) != len(files):
            raise RuntimeError('MISSING_EVIDENCE')
        for file in files:
            if file.get('status') not in ('added', 'removed', 'modified', 'renamed', 'copied', 'changed', 'unchanged'):
                raise RuntimeError('PROTOCOL_INVALID')
            for side in ('base', 'head'):
                if (side == 'base' and file['status'] == 'added') or (side == 'head' and file['status'] == 'removed'):
                    continue
                path = file.get('previous_filename', file['filename']) if side == 'base' else file['filename']
                source(path, revisions[side+'_oid'], 'changed_source')
    for path in contexts:
        source(path, revisions['head_oid'] if is_pr else revisions['repository_oid'], 'context_source')
    manifest = dict(identity, repository=request['repository'], **revisions,
                    policy_digest=request['policy_digest'], runtime_digest=request['runtime_digest'],
                    complete=all(e['disposition'] in ('required', 'excluded') for e in entries), pages_fetched=pages, pages_expected=pages, entries=entries,
                    thread_digest=canonical_digest(thread_entries), collection_receipts=receipts)
    manifest['evidence_digest'] = canonical_digest(manifest)
    return manifest
