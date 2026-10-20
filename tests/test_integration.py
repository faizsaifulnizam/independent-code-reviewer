"""Offline ordinary draft path. Doubles replace only GitHub and provider I/O."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import uuid
from datetime import datetime, timedelta, timezone


class DraftIntegrationTests(unittest.TestCase):
    def test_issue_draft_uses_real_collector_runner_validator_and_saves_artifact(self):
        self.run_issue_draft()

    def test_failed_final_refresh_is_partial_and_nonzero(self):
        self.run_issue_draft(refresh_failure='AUTH_FAILED')

    def run_issue_draft(self, refresh_failure=None):
        from reviewer.cli import main
        refresh_calls = 0
        root = Path(__file__).resolve().parents[1]
        policy_digest = hashlib.sha256((root/'config/review-policy.md').read_bytes()).hexdigest()
        runtime_digest = hashlib.sha256((root/'config/runtime.json').read_bytes()).hexdigest()
        request = {'schema_version':'0.2', 'request_id':str(uuid.uuid4()), 'repository_id':42,
                   'repository':'owner/repo', 'subject_kind':'issue', 'subject_number':2,
                   'mode':'draft', 'trigger':'manual', 'actor_id':7, 'grant_id':'trial',
                   'requested_effort':'high', 'policy_digest':policy_digest, 'runtime_digest':runtime_digest}
        grant = {'enabled':True, 'repository_id':42, 'repository':'owner/repo', 'actor_id':7,
                 'subjects':{'issue':[2]}, 'modes':['draft'], 'triggers':['manual'], 'efforts':['high'],
                 'policy_digest':policy_digest, 'runtime_digest':runtime_digest, 'provider':'opencode-go',
                 'model':'deepseek-v4.1-flash', 'max_responses':14, 'use_balance_off':True,
                 'context_paths':['examples/invoices.py'], 'public_only':True,
                 'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}
        github_reads = []
        class Source:
            def identity(self): return {'id':7}
            def get(self, path):
                nonlocal refresh_calls
                github_reads.append(path)
                if path == '/repos/owner/repo':
                    refresh_calls += 1
                    if refresh_calls == 2 and refresh_failure:
                        raise RuntimeError(refresh_failure)
                path = path.removeprefix('/')
                if path == 'repos/owner/repo':
                    return {'id':42,'full_name':'owner/repo','private':False,'default_branch':'main'}
                if '/git/ref/heads/' in path: return {'object':{'sha':'c'*40}}
                if '/contents/config/repositories.json?' in path:
                    raw = json.dumps({'schema_version':'0.2','version':1,'grants':{'trial':grant}}).encode()
                    return {'encoding':'base64','content':base64.b64encode(raw).decode()}
                if path == 'repos/owner/repo/issues/2':
                    return {'id':22,'number':2,'title':'Synthetic invoice access question',
                            'body':'When a user asks for another owner invoice, access must be denied.',
                            'updated_at':'2026-01-01T00:00:00Z','comments':0,'state':'open',
                            'repository_url':'https://api.github.com/repos/owner/repo',
                            'user':{'id':7},'html_url':'https://github.com/owner/repo/issues/2'}
                if '/comments?' in path: return []
                data = (root/'examples/invoices.py').read_bytes()
                blob_oid = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
                if '/git/commits/' in path:
                    return {'sha':'d'*40,'tree':{'sha':'a'*40}}
                if path.endswith('/git/trees/'+'a'*40):
                    return {'sha':'a'*40,'truncated':False,'tree':[{'path':'examples','type':'tree','mode':'040000','sha':'b'*40}]}
                if path.endswith('/git/trees/'+'b'*40):
                    return {'sha':'b'*40,'truncated':False,'tree':[{'path':'invoices.py','type':'blob','mode':'100644','sha':blob_oid,'size':len(data)}]}
                if '/git/blobs/' in path:
                    return {'encoding':'base64','size':len(data),'sha':blob_oid,'content':base64.b64encode(data).decode()}
                if '/commits/' in path: return {'sha':'d'*40}
                raise AssertionError('Unplanned GitHub path: '+path)
        calls = []
        class Socket:
            def settimeout(self, value): pass
        class Response(io.BytesIO):
            status = 200
            def getheader(self, name, default=None): return default
        class Connection:
            def __init__(self, *args, **kwargs): self.sock = Socket()
            def request(self, method, path, body=None, headers=None):
                packet = json.loads(body)
                calls.append(packet)
                refs = sorted(set(re.findall(r'\bE\d+\b', body.decode() if isinstance(body, bytes) else body)))
                if len(calls) == 1:
                    content = {'candidates':[], 'issue_assessment':{'conclusion':'needs_evidence',
                        'claims':[], 'missing_information':['A concrete failing reproduction is not supplied.'],
                        'reproduction_status':'not_run'}, 'missing_evidence':[],
                        'summary':'Synthetic fixture: no demonstrated defect in the supplied source.'}
                else:
                    content = {'scope_complete':True,'scope_evidence_refs':refs,
                        'assessment_agreement':'agree','votes':[],'late_candidates':[]}
                self.data = json.dumps({'id':'offline-'+str(len(calls)),
                    'model':'deepseek-v4.1-flash', 'choices':[{'finish_reason':'stop',
                    'message':{'role':'assistant','content':json.dumps(content)}}],
                    'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}}).encode()
            def getresponse(self): return Response(self.data)
            def close(self): pass
        scratch = os.environ.get('ICR_TEST_SCRATCH')
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            base = Path(directory)
            args = argparse.Namespace(control_repository='owner/repo', ledger=base/'budget.json', output=base/'draft')
            request_path = base/'request.json'
            request_path.write_text(json.dumps(request), encoding='utf-8')
            with patch('reviewer.cli.GitHubClient', return_value=Source()), \
                 patch('http.client.HTTPSConnection', Connection), \
                 patch.dict(os.environ, {'OPENCODE_GO_API_KEY':'offline-fixture-not-a-key'}):
                code = main(['draft','--request',str(request_path),'--output',str(args.output),
                             '--control-repository','owner/repo','--ledger',str(args.ledger)])
            self.assertEqual(code, 4 if refresh_failure else 0)
            artifact = json.loads((args.output/'review.json').read_text(encoding='utf-8'))
            self.assertEqual(artifact['outcome'], 'partial' if refresh_failure else 'completed_with_none')
            if refresh_failure:
                self.assertEqual(artifact['currentness'], 'unknown')
                self.assertIn('CURRENTNESS_UNKNOWN', artifact['limitations'])
            self.assertEqual(len(calls), 4)
            self.assertTrue(all(c['reasoning_effort'] == 'high' for c in calls))
            self.assertEqual(len(json.loads(args.ledger.read_text())['attempts']), 4)
            self.assertTrue((args.output/'review.md').is_file())
            self.assertGreater(len(github_reads), 8)
            self.assertNotIn('offline-fixture-not-a-key', json.dumps(artifact))


if __name__ == '__main__':
    unittest.main()
