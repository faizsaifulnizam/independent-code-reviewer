"""Caller seam: collect; only GitHub and live admission are boundary doubles."""
import copy
import unittest
import base64
import hashlib

HEAD = 'b' * 40
TREE = 'c' * 40
HEAD_TREE = 'd' * 40

def blob(text):
    raw = text.encode('utf-8')
    oid = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return oid, dict(sha=oid, encoding='base64', size=len(raw), content=base64.b64encode(raw).decode())

BASE = 'a' * 40
ROOT = '/repos/acme/demo'
REQUEST = dict(schema_version='0.2', request_id='12345678-1234-4234-8234-123456789abc', repository_id=7, repository='acme/demo', subject_kind='issue', subject_number=2, mode='draft', trigger='manual', actor_id=9, grant_id='g', policy_digest='1'*64, runtime_digest='2'*64, requested_effort='high')
GRANT = dict(repository_id=7, repository='acme/demo', public_only=True, context_paths=[])
LIMITS = dict(changed_paths=100, total_bytes=5242880, file_bytes=262144, thread_bytes=1048576, comments=1000)

class Source:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []
    def get(self, path):
        self.calls.append(path)
        if path not in self.routes:
            raise AssertionError('Unexpected GitHub read: ' + path)
        return copy.deepcopy(self.routes[path])


def issue_routes():
    return {ROOT: dict(id=7, full_name='acme/demo', owner={'login':'acme'}, private=False, visibility='public', default_branch='main'), ROOT+'/issues/2': dict(id=20, number=2, repository_url='https://api.github.com'+ROOT, body='A concrete issue\nSecond line', updated_at='2026-10-21T00:00:00Z', comments=1), ROOT+'/issues/2/comments?per_page=100&page=1': [dict(id=21, body='More evidence', updated_at='2026-10-21T00:01:00Z', issue_url='https://api.github.com'+ROOT+'/issues/2')], ROOT+'/commits/main': {'sha':BASE}}


def pr_routes():
    routes = issue_routes()
    routes[ROOT+'/pulls/2'] = dict(id=30, number=2, body='Change behavior', updated_at='2026-10-21T00:00:00Z', changed_files=1, comments=1, review_comments=1, base={'sha':BASE, 'repo':{'id':7, 'full_name':'acme/demo', 'private':False}}, head={'sha':HEAD, 'repo':{'id':7, 'full_name':'acme/demo', 'private':False}})
    routes[ROOT+'/pulls/2/files?per_page=100&page=1'] = [dict(filename='app.py', status='modified')]
    routes[ROOT+'/pulls/2/comments?per_page=100&page=1'] = [dict(id=31, body='Review comment', updated_at='2026-10-21T00:01:00Z', pull_request_url='https://api.github.com'+ROOT+'/pulls/2')]
    routes[ROOT+'/pulls/2/reviews?per_page=100&page=1'] = [dict(id=32, body='Review body', submitted_at='2026-10-21T00:02:00Z')]
    for revision, tree, text in [(BASE, TREE, 'answer = 1\n'), (HEAD, HEAD_TREE, 'answer = 2\n')]:
        oid, data = blob(text)
        routes[ROOT+'/git/commits/'+revision] = {'sha':revision, 'tree':{'sha':tree}}
        routes[ROOT+'/git/trees/'+tree] = dict(sha=tree, truncated=False, tree=[dict(path='app.py', mode='100644', type='blob', sha=oid, size=data['size'])])
        routes[ROOT+'/git/blobs/'+oid] = data
    return routes


class CollectorTests(unittest.TestCase):
    def run_collect(self, routes=None, request=None, grant=None, limits=None, admit=None):
        from reviewer.collect import collect
        self.source = Source(issue_routes() if routes is None else routes)
        self.admissions = []
        def allow(action, resource):
            self.admissions.append((action, resource))
            return {'allowed':True}
        return collect(request or REQUEST, grant or GRANT, self.source, limits or LIMITS, admit=admit or allow)

    def test_rejects_foreign_private_and_wrong_subject(self):
        mutations = [('repo_id', ROOT, 'id', 8), ('repo_name', ROOT, 'full_name', 'evil/demo'), ('private', ROOT, 'private', True), ('kind', ROOT+'/issues/2', 'pull_request', {}), ('number', ROOT+'/issues/2', 'number', 3), ('foreign_issue', ROOT+'/issues/2', 'repository_url', 'https://api.github.com/repos/evil/demo'), ('oid', ROOT+'/commits/main', 'sha', 'main')]
        for name, path, key, value in mutations:
            with self.subTest(name=name):
                routes = issue_routes()
                routes[path][key] = value
                with self.assertRaisesRegex(RuntimeError, 'NOT_AUTHORIZED|PROTOCOL_INVALID'):
                    self.run_collect(routes)

    def test_pr_pins_sources_and_full_discussion(self):
        m = self.run_collect(pr_routes(), request=dict(REQUEST, subject_kind='pull_request'))
        self.assertEqual((m['base_oid'], m['head_oid']), (BASE, HEAD))
        self.assertEqual([e['text'] for e in m['entries']], ['Change behavior', 'More evidence', 'Review comment', 'Review body', 'answer = 1\n', 'answer = 2\n'])
        self.assertEqual([e['revision'] for e in m['entries'] if e['kind']=='changed_source'], [BASE, HEAD])
        self.assertEqual(m['entries'][-1]['blob_digest'], hashlib.sha256(b'answer = 2\n').hexdigest())
        self.assertEqual(m['entries'][-1]['line_count'], 1)
        self.assertEqual(m['entries'][-1]['path'], 'app.py')
        self.assertTrue(m['complete'])

    def test_context_paths_and_nested_source(self):
        routes = pr_routes()
        nested = 'e'*40
        routes[ROOT+'/git/trees/'+TREE]['tree'] = [dict(path='src', type='tree', mode='040000', sha=nested)]
        routes[ROOT+'/git/trees/'+nested] = dict(sha=nested, truncated=False, tree=[dict(path='app.py', type='blob', mode='100644', sha=blob('answer = 1\n')[0], size=11)])
        grant = dict(GRANT, context_paths=['src/app.py'])
        limits = dict(LIMITS, context_paths=['src/app.py'])
        routes[ROOT+'/commits/main'] = {'sha':BASE}
        m = self.run_collect(routes, grant=grant, limits=limits)
        self.assertEqual(m['entries'][-1]['path'], 'src/app.py')
        self.assertEqual(m['entries'][-1]['kind'], 'context_source')
        self.assertEqual(m['entries'][-1]['text'], 'answer = 1\n')

    def test_scope_and_required_evidence_denials(self):
        for path in ['../app.py', '/app.py', 'src//app.py', 'src/./app.py', 'src\\\\app.py', 'https://evil/x', 'app.py?ref=x', 'app.py%2fsecret', 'app.py\x00']:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    self.run_collect(limits=dict(LIMITS, context_paths=[path]), grant=dict(GRANT, context_paths=[path]))
                self.assertEqual(self.source.calls, [])
        with self.assertRaisesRegex(RuntimeError, 'NOT_AUTHORIZED'):
            self.run_collect(limits=dict(LIMITS, context_paths=['app.py']))
        self.assertEqual(self.source.calls, [])
        routes = pr_routes()
        routes[ROOT+'/pulls/2']['head']['repo']['id'] = 99
        with self.assertRaisesRegex(RuntimeError, 'NOT_AUTHORIZED'):
            self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))
        for change in ('missing', 'count', 'truncated', 'foreign_blob'):
            routes = pr_routes()
            if change == 'missing':
                routes[ROOT+'/git/trees/'+TREE]['tree'] = []
            elif change == 'count':
                routes[ROOT+'/pulls/2']['changed_files'] = 2
            elif change == 'truncated':
                routes[ROOT+'/git/trees/'+TREE]['truncated'] = True
            else:
                routes[ROOT+'/git/blobs/'+blob('answer = 1\n')[0]]['content'] = base64.b64encode(b'wrong bytes').decode()
            with self.subTest(change=change):
                with self.assertRaisesRegex(RuntimeError, 'MISSING_EVIDENCE|PROTOCOL_INVALID'):
                    self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))

    def test_pagination_and_revocation_between_pages(self):
        routes = issue_routes()
        page1 = ROOT+'/issues/2/comments?per_page=100&page=1'
        page2 = ROOT+'/issues/2/comments?per_page=100&page=2'
        routes[page1] = [dict(routes[page1][0], id=100+i) for i in range(100)]
        routes[page2] = [dict(routes[page1][0], id=200)]
        routes[ROOT+'/issues/2']['comments'] = 101
        m = self.run_collect(routes)
        self.assertEqual(len(m['entries']), 102)
        self.assertEqual(m['pages_fetched'], 2)
        def revoke(action, resource):
            return {'allowed':False, 'reason':'REVOKED'} if resource.get('page') == 2 else {'allowed':True}
        with self.assertRaisesRegex(RuntimeError, '^REVOKED$'):
            self.run_collect(routes, admit=revoke)
        self.assertNotIn(page2, self.source.calls)

    def test_caps_before_unbounded_collection(self):
        for name, maximum in [('thread_bytes', 10), ('total_bytes', 10), ('comments', 0)]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, '^PAYLOAD_LIMIT$'):
                    self.run_collect(limits=dict(LIMITS, **{name:maximum}))
        for name, maximum in [('file_bytes', 10), ('changed_paths', 0)]:
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, '^PAYLOAD_LIMIT$'):
                    self.run_collect(pr_routes(), request=dict(REQUEST, subject_kind='pull_request'), limits=dict(LIMITS, **{name:maximum}))
                self.assertFalse(any('/git/blobs/' in path for path in self.source.calls))
        for invalid in [True, -1, 1.1, 5242881]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.run_collect(limits=dict(LIMITS, total_bytes=invalid))
                self.assertEqual(self.source.calls, [])
        routes = issue_routes()
        routes[ROOT+'/issues/2']['comments'] = 2
        with self.assertRaisesRegex(RuntimeError, '^MISSING_EVIDENCE$'):
            self.run_collect(routes)

    def test_exclusions_and_secret_gaps_never_export_unsafe_content(self):
        cases = [('symlink', '120000', 'blob', 'target.py', 'excluded'), ('submodule', '160000', 'commit', 'gitref', 'excluded'), ('binary', '100644', 'blob', 'abc\x00def', 'excluded'), ('lfs', '100644', 'blob', 'version https://git-lfs.github.com/spec/v1\noid sha256:'+'f'*64+'\nsize 123\n', 'excluded'), ('secret', '100644', 'blob', 'api_key = "'+'X'*32+'"', 'withheld')]
        for name, mode, kind, text, disposition in cases:
            with self.subTest(name=name):
                routes = pr_routes()
                oid, data = blob(text)
                routes[ROOT+'/git/trees/'+TREE]['tree'] = [dict(path='app.py', mode=mode, type=kind, sha=oid, size=data['size'])]
                routes[ROOT+'/git/blobs/'+oid] = data
                m = self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))
                e = next(e for e in m['entries'] if e.get('revision') == BASE)
                self.assertEqual(e['disposition'], disposition)
                self.assertEqual(e['text'], '')
                self.assertTrue(e['reason'])
                self.assertEqual(m['complete'], disposition != 'withheld')
                if name in ('symlink', 'submodule'):
                    self.assertNotIn(ROOT+'/git/blobs/'+oid, self.source.calls)
        routes = pr_routes()
        routes[ROOT+'/pulls/2/files?per_page=100&page=1'] = [dict(filename='.env', status='added')]
        m = self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))
        self.assertEqual(m['entries'][-1]['disposition'], 'withheld')
        self.assertFalse(m['complete'])
        self.assertFalse(any('/git/' in p for p in self.source.calls))
        routes = issue_routes()
        routes[ROOT+'/issues/2']['body'] = '-----BEGIN PRIVATE KEY-----\nsensitive material'
        m = self.run_collect(routes)
        self.assertEqual(m['entries'][0]['disposition'], 'withheld')
        self.assertEqual(m['entries'][0]['text'], '')
        self.assertNotIn('sensitive material', str(m))

    def test_protocol_identity_is_not_inferred_from_endpoint(self):
        for change in ('foreign_comment', 'duplicate_comment', 'bad_id', 'body_type', 'bad_commit', 'bad_encoding', 'unknown_status'):
            routes = pr_routes()
            if change == 'foreign_comment':
                routes[ROOT+'/issues/2/comments?per_page=100&page=1'][0]['issue_url'] = 'https://api.github.com/repos/evil/demo/issues/2'
            elif change == 'duplicate_comment':
                routes[ROOT+'/pulls/2/comments?per_page=100&page=1'] *= 2
            elif change == 'bad_id':
                routes[ROOT+'/pulls/2']['id'] = True
            elif change == 'body_type':
                routes[ROOT+'/pulls/2']['body'] = ['not text']
            elif change == 'bad_commit':
                routes[ROOT+'/git/commits/'+BASE]['sha'] = HEAD
            elif change == 'bad_encoding':
                routes[ROOT+'/git/blobs/'+blob('answer = 1\n')[0]]['encoding'] = 'unsupported'
            else:
                routes[ROOT+'/pulls/2/files?per_page=100&page=1'][0]['status'] = 'unknown'
            with self.subTest(change=change):
                with self.assertRaisesRegex(RuntimeError, 'PROTOCOL_INVALID|NOT_AUTHORIZED|MISSING_EVIDENCE'):
                    self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))

    def test_paginated_pr_files_are_fully_accounted_for(self):
        routes = pr_routes()
        filenames = [f'file{i}.py' for i in range(100)]
        routes[ROOT+'/pulls/2']['changed_files'] = 100
        routes[ROOT+'/pulls/2/files?per_page=100&page=1'] = [dict(filename=p, status='added') for p in filenames]
        routes[ROOT+'/pulls/2/files?per_page=100&page=2'] = []
        item = routes[ROOT+'/git/trees/'+HEAD_TREE]['tree'][0]
        routes[ROOT+'/git/trees/'+HEAD_TREE]['tree'] = [dict(item, path=p) for p in filenames]
        m = self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))
        self.assertEqual([e['path'] for e in m['entries'] if e['kind']=='changed_source'], filenames)
        self.assertIn(ROOT+'/pulls/2/files?per_page=100&page=2', self.source.calls)
        self.assertEqual(m['pages_fetched'], 5)

    def test_missing_review_comments_and_unbounded_context_deny(self):
        routes = pr_routes()
        routes[ROOT+'/pulls/2']['review_comments'] = 2
        with self.assertRaisesRegex(RuntimeError, '^MISSING_EVIDENCE$'):
            self.run_collect(routes, request=dict(REQUEST, subject_kind='pull_request'))
        paths = [f'file{i}.py' for i in range(101)]
        with self.assertRaisesRegex(RuntimeError, '^PAYLOAD_LIMIT$'):
            self.run_collect(limits=dict(LIMITS, context_paths=paths), grant=dict(GRANT, context_paths=paths))
        self.assertEqual(self.source.calls, [])

    def test_malformed_github_objects_have_sanitized_errors(self):
        for path, value in [(ROOT, []), (ROOT+'/issues/2', {}), (ROOT+'/issues/2', dict(issue_routes()[ROOT+'/issues/2'], body='\ud800'))]:
            with self.subTest(path=path, value_type=type(value).__name__):
                routes = issue_routes()
                routes[path] = value
                with self.assertRaisesRegex(RuntimeError, '^PROTOCOL_INVALID$|^NOT_AUTHORIZED$'):
                    self.run_collect(routes)

    def test_canonical_public_repo_uses_rest_identity_fields(self):
        routes = issue_routes()
        del routes[ROOT]['visibility']
        del routes[ROOT]['owner']
        m = self.run_collect(routes)
        self.assertTrue(m['complete'])

    def test_issue_snapshot_and_admission(self):
        m = self.run_collect()
        self.assertTrue(m['complete'])
        self.assertEqual(m['repository_oid'], BASE)
        self.assertEqual([e['text'] for e in m['entries']], ['A concrete issue\nSecond line', 'More evidence'])
        self.assertEqual(m['entries'][0]['issue_object_id'], 20)
        self.assertEqual(m['entries'][0]['line_count'], 2)
        self.assertEqual(m['entries'][0]['byte_count'], 28)
        self.assertEqual(len(self.admissions), len(self.source.calls))
        for (action, resource), path in zip(self.admissions, self.source.calls):
            self.assertEqual(action, 'read_evidence')
            self.assertEqual(resource['api_path'], path)
            self.assertEqual(resource['repository_id'], 7)
        from reviewer.validate import canonical_digest
        self.assertEqual(m['evidence_digest'], canonical_digest({k:v for k,v in m.items() if k != 'evidence_digest'}))

if __name__ == '__main__':
    unittest.main()
