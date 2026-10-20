import base64
import os
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('ICR_TEST_SCRATCH'))
        self.addCleanup(self.temp.cleanup)
        self.ledger = Path(self.temp.name)/'budget.json'
        self.request = {'request_id': 'request', 'repository_id': 42, 'repository': 'owner/repo',
                        'subject_kind': 'issue', 'subject_number': 2, 'actor_id': 7,
                        'grant_id': 'trial', 'mode': 'draft', 'trigger': 'manual',
                        'requested_effort': 'high', 'policy_digest': 'a'*64, 'runtime_digest': 'b'*64}
        self.grant = {'enabled': True, 'repository_id': 42, 'repository': 'owner/repo',
                      'actor_id': 7, 'subjects': {'issue': [2], 'pull_request': [1]},
                      'modes': ['draft'], 'triggers': ['manual'], 'efforts': ['high'],
                      'provider': 'opencode-go', 'model': 'deepseek-v4.1-flash',
                      'policy_digest': 'a'*64, 'runtime_digest': 'b'*64,
                      'max_responses': 14, 'use_balance_off': True, 'public_only': True,
                      'context_paths': ['app.py'], 'limits': {'file_bytes': 262144},
                      'expires_at': (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}
        outer = self
        class Source:
            def get(self, path):
                if path == 'repos/owner/repo':
                    return {'id': 42, 'full_name': 'owner/repo', 'private': False, 'default_branch': 'main'}
                if path.endswith('/git/ref/heads/main'):
                    return {'object': {'sha': 'c'*40}}
                if '/contents/config/repositories.json?' in path:
                    data = json.dumps({'schema_version': '0.2', 'version': 1,
                                       'grants': {'trial': outer.grant}}).encode()
                    return {'encoding': 'base64', 'content': base64.b64encode(data).decode()}
                raise AssertionError(path)
        self.source = Source()

    def authority(self):
        from reviewer.cli import Authority
        return Authority(self.request, self.source, 'owner/repo', self.ledger,
                         time.monotonic()+20, run_id='run')

    def resource(self, attempt='attempt-1'):
        return {**{k:self.request[k] for k in ('request_id','repository_id','subject_kind','subject_number',
                                             'policy_digest','runtime_digest')},
                'run_id':'run','slot':'finder','attempt_id':attempt,'provider':'opencode-go',
                'model':'deepseek-v4.1-flash','effort':'high','evidence_digest':'d'*64}

    def test_revocation_after_first_admission_prevents_next_attempt(self):
        authority = self.authority()
        self.assertTrue(authority('model_request', self.resource())['allowed'])
        self.grant['enabled'] = False
        self.assertFalse(authority('model_request', self.resource('attempt-2'))['allowed'])
        self.assertEqual(len(json.loads(self.ledger.read_text())['attempts']), 1)

    def test_unconfirmed_no_overage_setting_denies_before_reservation(self):
        self.grant['use_balance_off'] = False
        authority = self.authority()
        self.assertFalse(authority('model_request', self.resource())['allowed'])
        self.assertFalse(self.ledger.exists())

    def test_concurrent_last_slot_has_one_reservation(self):
        self.grant['max_responses'] = 1
        authority = self.authority()
        results = []
        threads = [threading.Thread(target=lambda i=i: results.append(
            authority('model_request', self.resource('attempt-'+str(i))))) for i in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(r['allowed'] for r in results), 1)
        self.assertEqual(len(json.loads(self.ledger.read_text())['attempts']), 1)

    def test_draft_rejects_revoked_remote_grant_before_model_use(self):
        import argparse
        import hashlib
        from unittest.mock import patch
        from reviewer.cli import execute_draft
        root = Path(__file__).resolve().parents[1]
        self.request['policy_digest'] = hashlib.sha256((root/'config/review-policy.md').read_bytes()).hexdigest()
        self.request['runtime_digest'] = hashlib.sha256((root/'config/runtime.json').read_bytes()).hexdigest()
        self.grant.update(policy_digest=self.request['policy_digest'], runtime_digest=self.request['runtime_digest'], enabled=False)
        self.source.identity = lambda: {'id': 7}
        args = argparse.Namespace(control_repository='owner/repo', ledger=self.ledger,
                                  output=Path(self.temp.name)/'draft')
        with patch('reviewer.cli.GitHubClient', return_value=self.source):
            with self.assertRaisesRegex(RuntimeError, 'REVOKED'):
                execute_draft(self.request, args)
        self.assertFalse(self.ledger.exists())

    def test_bound_read_requires_exact_digest_and_valid_line_range(self):
        authority = self.authority()
        authority.bind_manifest({'entries':[{'evidence_id':'E001','blob_digest':'d'*64,
                                             'line_count':3,'disposition':'required'}]})
        resource = {k:self.request[k] for k in ('request_id','repository_id','subject_kind','subject_number')}
        resource.update(evidence_id='E001', digest='d'*64, start_line=1, end_line=3)
        self.assertTrue(authority('read_evidence', resource)['allowed'])
        self.assertFalse(authority('read_evidence', dict(resource,digest='e'*64))['allowed'])
        self.assertFalse(authority('read_evidence', dict(resource,end_line=4))['allowed'])

    def test_changed_evidence_scope_denies_bound_reads_and_model_attempts(self):
        for key, value in (('context_paths', []), ('limits', {'file_bytes': 1}),
                           ('public_only', False), ('context_paths', ['app.py', 'more.py'])):
            with self.subTest(key=key, value=value):
                original = json.loads(json.dumps(self.grant))
                authority = self.authority()
                authority.bind_manifest({'evidence_digest': 'd'*64, 'entries': [
                    {'evidence_id': 'E001', 'blob_digest': 'd'*64,
                     'line_count': 3, 'disposition': 'required'}]})
                read = {k: self.request[k] for k in
                        ('request_id', 'repository_id', 'subject_kind', 'subject_number')}
                read.update(evidence_id='E001', digest='d'*64, start_line=1, end_line=3)
                self.assertTrue(authority('read_evidence', read)['allowed'])
                self.grant[key] = value
                self.assertFalse(authority('read_evidence', read)['allowed'])
                self.assertFalse(authority('model_request', self.resource())['allowed'])
                self.assertFalse(self.ledger.exists())
                self.grant = original

    def test_public_only_required_initially(self):
        self.grant.pop('public_only')
        authority = self.authority()
        self.assertFalse(authority('model_request', self.resource())['allowed'])
        self.assertFalse(self.ledger.exists())

    def test_runtime_wall_cap_reaches_client_before_network(self):
        import argparse
        from unittest.mock import patch
        from reviewer.cli import execute_draft
        root = Path(__file__).resolve().parents[1]
        runtime_path = root / 'config/runtime.json'
        runtime = json.loads(runtime_path.read_bytes())
        real_read = Path.read_bytes
        self.request['policy_digest'] = hashlib.sha256((root/'config/review-policy.md').read_bytes()).hexdigest()
        args = argparse.Namespace(control_repository='owner/repo', ledger=self.ledger,
                                  output=Path(self.temp.name)/'draft')
        for wall in (10, 900, 5, 0, 901, True, 10.5, float('inf')):
            with self.subTest(wall=wall):
                data = json.dumps(dict(runtime, wall_time_s=wall)).encode()
                self.request['runtime_digest'] = hashlib.sha256(data).hexdigest()
                observed = []
                def stop(repository, deadline):
                    observed.append(deadline)
                    raise RuntimeError('STOP_OFFLINE')
                def read(path):
                    return data if path == runtime_path else real_read(path)
                valid = type(wall) is int and 5 < wall <= 900
                with patch.object(Path, 'read_bytes', read), \
                     patch('reviewer.cli.time.monotonic', side_effect=[100, 103]), \
                     patch('reviewer.cli.GitHubClient', side_effect=stop):
                    if valid:
                        with self.assertRaisesRegex(RuntimeError, 'STOP_OFFLINE'):
                            execute_draft(self.request, args)
                        self.assertEqual(observed, [100 + wall])
                    else:
                        with self.assertRaises(ValueError):
                            execute_draft(self.request, args)
                        self.assertEqual(observed, [])

    def test_foreign_subject_and_unknown_action_deny(self):
        authority = self.authority()
        resource = self.resource()
        resource['subject_number'] = 99
        self.assertFalse(authority('model_request', resource)['allowed'])
        self.assertFalse(authority('publish_comment', self.resource())['allowed'])
        self.assertFalse(self.ledger.exists())


if __name__ == '__main__':
    unittest.main()
