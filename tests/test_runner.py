"""Offline caller tests; HTTPSConnection is the only substituted provider boundary."""
import copy
import io
import json
import os
import socket
import time
import unittest
from unittest.mock import patch

from reviewer.runner import review


class Socket:
    def settimeout(self, timeout):
        assert timeout > 0


class Response(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status


class Provider:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []
        self.closed = 0
        self.response_objects = []
        self.sock = Socket()

    def connect(self, host, **kwargs):
        assert host == 'opencode.ai'
        assert 0 < kwargs['timeout'] <= 60
        return self

    def request(self, method, path, body, headers):
        assert method == 'POST'
        assert path == '/zen/go/v1/chat/completions'
        assert headers['Authorization'] == 'Bearer fixture-only'
        self.requests.append(json.loads(body))

    def getresponse(self):
        status, body = next(self.responses)
        response = Response(status, body)
        self.response_objects.append(response)
        return response

    def close(self):
        self.closed += 1


def wire(content, **extra):
    return (200, json.dumps(dict(id='fixture-response', model='observed-model',
        choices=[{'message': {'content': json.dumps(content), 'reasoning_content': 'PRIVATE_REASONING'}}],
        usage={'prompt_tokens': 10, 'completion_tokens': 5}, **extra)).encode())


def tool_wire():
    return (200,json.dumps({'id':'tool-response','choices':[{'message':{'content':None,
        'tool_calls':[{'id':'read-1','type':'function','function':{'name':'read_evidence',
            'arguments':json.dumps({'evidence_id':'E001','start_line':1,'end_line':1})}}]}}]}).encode())


def finder():
    return dict(candidates=[], issue_assessment=None, missing_evidence=[], summary='No candidates')


def juror():
    return dict(scope_complete=True, scope_evidence_refs=['E001'], assessment_agreement=None,
                votes=[], late_candidates=[])


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.manifest = dict(request_id='00000000-0000-4000-8000-000000000001', repository_id=1,
            repository='owner/repo', subject_kind='pull_request', subject_number=1,
            policy_digest='a'*64, runtime_digest='b'*64, evidence_digest='c'*64, complete=True,
            entries=[dict(evidence_id='E001', disposition='required', text='line one\nline two\n',
                          blob_digest='d'*64, path='src/a.py', line_count=2)])
        self.runtime = dict(provider='opencode-go', model='deepseek-v4.1-flash',
            endpoint='https://opencode.ai/zen/go/v1/chat/completions', effort='high',
            run_id='00000000-0000-4000-8000-000000000002', policy_digest='a'*64,
            runtime_digest='b'*64, **{k:self.manifest[k] for k in
            ('request_id','repository_id','subject_kind','subject_number')})
        self.budget = dict(deadline=time.monotonic()+100, cleanup_reserve=5, max_responses=7,
            max_input_bytes=131072, max_response_bytes=1048576, max_output_tokens=4096,
            network_timeout=60)
        self.effects = []

    def admit(self, action, resource):
        self.effects.append((action, copy.deepcopy(resource)))
        return {'allowed': True, 'grant_version': 1}

    def run_review(self, responses, admit=None):
        provider = Provider(responses)
        self.last_provider = provider
        with patch.dict(os.environ, {'OPENCODE_GO_API_KEY': 'fixture-only'}), \
             patch('http.client.HTTPSConnection', provider.connect), \
             patch.object(socket.socket, 'connect', side_effect=AssertionError('OUTBOUND SOCKET')), \
             patch('socket.create_connection', side_effect=AssertionError('OUTBOUND SOCKET')):
            result = review(self.manifest, 'Approved policy', self.runtime, self.budget,
                            admit=admit or self.admit)
        return result, provider

    def test_empty_batch_requires_three_isolated_audits(self):
        result, provider = self.run_review([wire(finder())] + [wire(juror())]*3)
        self.assertEqual([b['juror_id'] for b in result['juror_batches']], ['J1','J2','J3'])
        self.assertEqual(result['execution']['actual_response_count'], 4)
        self.assertEqual(result['execution']['uncertain_attempts'], 0)
        self.assertEqual(len(provider.requests), 4)
        self.assertEqual(provider.requests[1:], [provider.requests[1]]*3)
        self.assertNotIn('PRIVATE_REASONING', json.dumps(result))
        self.assertNotIn('fixture-only', json.dumps(provider.requests))
        self.assertEqual([x[0] for x in self.effects], ['read_evidence']+['model_request']*4)
        self.assertEqual(result['read_receipts'][0]['end_line'], 2)
        for request in provider.requests:
            self.assertEqual(request['reasoning_effort'], 'high')
        self.assertEqual(provider.closed, 4)
        self.assertTrue(all(r['admission']['allowed'] is True for r in result['execution']['response_receipts']))


    def test_http_errors_are_single_attempt_and_accounted(self):
        for status, reason in [(503,'MODEL_UNAVAILABLE'),(401,'AUTH_FAILED'),(429,'QUOTA_EXHAUSTED'),(302,'MODEL_UNAVAILABLE')]:
            with self.subTest(status=status):
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([(status,b'provider detail MUST NOT ESCAPE')])
                self.assertEqual(str(caught.exception), reason)
                self.assertEqual(caught.exception.execution['actual_response_count'], 1)
                self.assertEqual(caught.exception.execution['uncertain_attempts'], 0)
                self.assertEqual(len(caught.exception.execution['response_receipts']), 1)
                self.assertNotIn('MUST NOT ESCAPE', repr(caught.exception.execution))

    def test_bounded_success_error_and_malformed_protocol(self):
        for status, body, reason in [(200,b'x'*1048577,'PROVIDER_OUTPUT_LIMIT'),
                (503,b'x'*1048577,'PROVIDER_OUTPUT_LIMIT'),(200,b'{','PROTOCOL_INVALID'),
                (200,b'{"choices":[],"choices":[]}','PROTOCOL_INVALID'),
                (200,b'{"choices":[]}','PROTOCOL_INVALID')]:
            with self.subTest(status=status, reason=reason):
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([(status,body)])
                self.assertEqual(str(caught.exception), reason)
                self.assertEqual(len(caught.exception.execution['response_receipts']), 1)


    def test_fresh_admission_denies_without_dispatch(self):
        for allowed, reason in [(False,'REVOKED'),(1,'CANCELLED'),(None,'NOT_AUTHORIZED')]:
            with self.subTest(allowed=allowed):
                def denied(action, resource):
                    return {'allowed':allowed,'reason':reason}
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([], admit=denied)
                self.assertEqual(str(caught.exception), reason)
                self.assertEqual(caught.exception.execution['actual_response_count'], 0)

    def test_cancel_before_second_model_effect_keeps_first_receipt(self):
        def cancel(action, resource):
            if action == 'model_request' and resource['slot'] == 'J1':
                return {'allowed':False,'reason':'CANCELLED'}
            return self.admit(action,resource)
        with self.assertRaises(RuntimeError) as caught:
            self.run_review([wire(finder())], admit=cancel)
        self.assertEqual(str(caught.exception), 'CANCELLED')
        self.assertEqual(caught.exception.execution['actual_response_count'], 1)

    def test_deadline_before_and_after_admission(self):
        for after in (False,True):
            with self.subTest(after=after):
                self.budget['deadline'] = time.monotonic()+100 if after else time.monotonic()-1
                def expire(action, resource):
                    self.budget['deadline'] = time.monotonic()-1
                    return {'allowed':True}
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([],admit=expire)
                self.assertEqual(str(caught.exception),'TIME_BUDGET')
                self.assertEqual(caught.exception.execution['uncertain_attempts'],0)

    def test_input_and_response_count_caps_precede_dispatch(self):
        for key, value, reason in [('max_input_bytes',1,'PAYLOAD_LIMIT'),('max_responses',0,'RESPONSE_BUDGET')]:
            with self.subTest(key=key):
                old = self.budget[key]
                self.budget[key] = value
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([])
                self.assertEqual(str(caught.exception),reason)
                self.assertFalse(any(x[0]=='model_request' for x in self.effects))
                self.budget[key] = old
                self.effects.clear()


    def test_remaining_timeout_and_drip_deadline_are_aggregate(self):
        clock = [100.0]
        self.budget['deadline'] = 108.0
        class Drip(Response):
            def read1(self, count):
                clock[0] += 1.0
                return super().read(1)
            def read(self, count=-1):
                raise AssertionError('unbounded/blocking read instead of read1')
        with patch('time.monotonic',side_effect=lambda:clock[0]), \
             patch.object(Provider,'getresponse',return_value=Drip(200,b'x'*100)):
            with self.assertRaises(RuntimeError) as caught:
                self.run_review([])
        self.assertEqual(str(caught.exception),'TIME_BUDGET')
        self.assertLessEqual(clock[0],103.0)
        self.assertEqual(caught.exception.execution['uncertain_attempts'],1)

    def test_transport_failure_is_uncertain_and_never_retried(self):
        with patch.object(Provider,'getresponse',side_effect=OSError('sensitive detail')):
            with self.assertRaises(RuntimeError) as caught:
                self.run_review([])
        self.assertEqual(str(caught.exception),'MODEL_UNAVAILABLE')
        self.assertEqual(caught.exception.execution['uncertain_attempts'],1)
        self.assertEqual(caught.exception.execution['actual_response_count'],0)
        self.assertEqual(len(caught.exception.execution['response_receipts']),1)


    def test_finder_tools_are_bounded_and_not_shared_with_jurors(self):
        result, provider = self.run_review([tool_wire(),wire(finder())]+[wire(juror())]*3)
        self.assertEqual(result['execution']['actual_response_count'],5)
        self.assertEqual(len(result['read_receipts']),2)
        self.assertIn('tools',provider.requests[0])
        self.assertEqual(provider.requests[1]['messages'][-1]['role'],'tool')
        self.assertNotIn('tools',provider.requests[2])
        self.assertNotIn('read-1',json.dumps(provider.requests[2:]))
        self.assertEqual(provider.requests[2:], [provider.requests[2]]*3)

    def test_finder_never_exceeds_four_responses(self):
        with self.assertRaises(RuntimeError) as caught:
            self.run_review([tool_wire()]*4)
        self.assertEqual(str(caught.exception),'RESPONSE_BUDGET')
        self.assertEqual(caught.exception.execution['actual_response_count'],4)

    def test_large_initial_evidence_is_split_into_64k_reads(self):
        self.manifest['entries'][0].update(text=('x'*40000+'\n')*2,line_count=2)
        result,_ = self.run_review([wire(finder())]+[wire(juror())]*3)
        self.assertEqual([(r['start_line'],r['end_line']) for r in result['read_receipts']],[(1,1),(2,2)])

    def test_juror_tools_are_rejected_without_continuation(self):
        with self.assertRaises(RuntimeError) as caught:
            self.run_review([wire(finder()),tool_wire()])
        self.assertEqual(str(caught.exception),'PROTOCOL_INVALID')
        self.assertEqual(caught.exception.execution['actual_response_count'],2)


    def test_runtime_and_nonfinite_budget_rejected_before_effects(self):
        for key,value in [('endpoint','https://evil.invalid/'),('provider','other'),('model','other'),('effort','low')]:
            with self.subTest(key=key):
                original=self.runtime[key]
                self.runtime[key]=value
                with self.assertRaises(ValueError):
                    self.run_review([])
                self.runtime[key]=original
        self.budget['deadline']=float('nan')
        with self.assertRaises(ValueError):
            self.run_review([])
        self.assertEqual(self.effects,[])

    def test_strict_content_envelopes_cannot_mint_identities_or_reasoning(self):
        for payload in [dict(finder(),reasoning_content='SECRET'),dict(finder(),candidates='wrong'),
                        dict(finder(),issue_assessment={}),dict(finder(),missing_evidence=None)]:
            with self.subTest(payload=payload):
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([wire(payload)])
                self.assertEqual(str(caught.exception),'PROTOCOL_INVALID')
                self.assertEqual(caught.exception.execution['actual_response_count'],1)
        for payload in [dict(juror(),juror_id='J3'),dict(juror(),scope_complete=1),dict(juror(),votes={})]:
            with self.subTest(payload=payload):
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([wire(finder()),wire(payload)])
                self.assertEqual(str(caught.exception),'PROTOCOL_INVALID')
                self.assertEqual(caught.exception.execution['actual_response_count'],2)

    def test_issue_assessment_and_max_effort_keep_frozen_inputs(self):
        self.manifest['subject_kind']='issue'
        self.runtime.update(subject_kind='issue',effort='max')
        assessment=dict(conclusion='needs_evidence',claims=[],missing_information=['logs'],reproduction_status='not_run')
        found=dict(finder(),issue_assessment=assessment,summary='FINDER_PRIVATE_SUMMARY')
        ballots=[dict(juror(),assessment_agreement='agree'),dict(juror(),assessment_agreement='uncertain'),
                 dict(juror(),assessment_agreement='disagree')]
        result,provider=self.run_review([wire(found)]+[wire(b) for b in ballots])
        self.assertEqual(result['issue_assessment'],assessment)
        self.assertEqual(provider.requests[1:], [provider.requests[1]]*3)
        self.assertNotIn('FINDER_PRIVATE_SUMMARY',json.dumps(provider.requests[1:]))
        self.assertTrue(all(r['reasoning_effort']=='max' for r in provider.requests))
        self.assertEqual(len({r['attempt_id'] for r in result['execution']['response_receipts']}),4)


    def test_candidate_and_ballots_have_no_private_extras(self):
        anchor=dict(evidence_id='E001',path='src/a.py',blob_digest='d'*64,start_line=1,end_line=1)
        candidate=dict(candidate_id='C1',severity='high',confidence='high',title='Reachable failure',
            trigger='input',mechanism='branch',impact='failure',anchors=[anchor],evidence_class='reasoned_path',
            evidence_refs=['E001'],verification_step={'description':'add a test','status':'not_run'})
        vote=dict(candidate_id='C1',vote='supported',reason='concrete path',anchors=[anchor],
            evidence_refs=['E001'],counterevidence_refs=[],trigger='input',mechanism='branch',impact='failure')
        found=dict(finder(),candidates=[candidate])
        ballot=dict(juror(),votes=[vote])
        result,provider=self.run_review([wire(found)]+[wire(ballot)]*3)
        self.assertEqual(result['candidates'][0]['finding_id'],'C1')
        self.assertEqual(provider.requests[1:],[provider.requests[1]]*3)
        for where in ('candidate','vote'):
            with self.subTest(where=where):
                bad_found=copy.deepcopy(found)
                bad_ballot=copy.deepcopy(ballot)
                if where=='candidate':
                    bad_found['candidates'][0]['reasoning_content']='PRIVATE'
                else:
                    bad_ballot['votes'][0]['reasoning_content']='PRIVATE'
                with self.assertRaises(RuntimeError) as caught:
                    self.run_review([wire(bad_found),wire(bad_ballot)])
                self.assertEqual(str(caught.exception),'PROTOCOL_INVALID')

    def test_actual_stdlib_http_stack_at_connect_boundary(self):
        # Characterization: only TLS/socket establishment is substituted, not HTTP encoding/parsing.
        import http.client
        responses=iter([wire(finder())]+[wire(juror())]*3)
        sent=[]
        class WireSocket:
            def __init__(self, body):
                self.body=body
            def sendall(self,data):
                sent.append(data)
            def makefile(self,mode):
                return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(self.body)).encode()+
                    b'\r\nConnection: close\r\n\r\n'+self.body)
            def settimeout(self,value):
                assert 0 < value <= 60
            def close(self):
                pass
        def connect(connection):
            _,body=next(responses)
            connection.sock=WireSocket(body)
        with patch.dict(os.environ,{'OPENCODE_GO_API_KEY':'fixture-only'}), \
             patch.object(http.client.HTTPSConnection,'connect',connect), \
             patch.object(socket.socket,'connect',side_effect=AssertionError('OUTBOUND')) as outbound, \
             patch('socket.getaddrinfo',side_effect=AssertionError('DNS OUTBOUND')) as dns:
            result=review(self.manifest,'Approved policy',self.runtime,self.budget,admit=self.admit)
        self.assertEqual(result['execution']['actual_response_count'],4)
        self.assertEqual(len([chunk for chunk in sent if chunk.startswith(b'POST ')]),4)
        self.assertTrue(any(b'Authorization: Bearer fixture-only' in chunk for chunk in sent))
        outbound.assert_not_called()
        dns.assert_not_called()


    def test_missing_credential_and_incomplete_manifest_never_dispatch(self):
        with patch.dict(os.environ,{},clear=True), \
             patch('http.client.HTTPSConnection',side_effect=AssertionError('NO DISPATCH')):
            with self.assertRaises(RuntimeError) as caught:
                review(self.manifest,'Approved policy',self.runtime,self.budget,admit=self.admit)
        self.assertEqual(str(caught.exception),'AUTH_FAILED')
        self.assertFalse(caught.exception.execution['response_receipts'])
        self.manifest['complete']=False
        with self.assertRaises(RuntimeError) as caught:
            self.run_review([])
        self.assertEqual(str(caught.exception),'MISSING_EVIDENCE')
        self.assertFalse(caught.exception.execution['response_receipts'])

    def test_seven_response_schedule_and_invalid_tool_targets(self):
        result,_=self.run_review([tool_wire()]*3+[wire(finder())]+[wire(juror())]*3)
        self.assertEqual(result['execution']['actual_response_count'],7)
        self.assertEqual([r['slot'] for r in result['execution']['response_receipts']],['finder']*4+['J1','J2','J3'])
        for arguments,reason in [({'evidence_id':'foreign','start_line':1,'end_line':1},'MISSING_EVIDENCE'),
                ({'evidence_id':'E001','start_line':True,'end_line':1},'PROTOCOL_INVALID'),
                ({'evidence_id':'E001','start_line':0,'end_line':1},'PROTOCOL_INVALID'),
                ({'evidence_id':'E001','start_line':1,'end_line':99},'PROTOCOL_INVALID')]:
            body=json.loads(tool_wire()[1])
            body['choices'][0]['message']['tool_calls'][0]['function']['arguments']=json.dumps(arguments)
            with self.subTest(arguments=arguments),self.assertRaises(RuntimeError) as caught:
                self.run_review([(200,json.dumps(body).encode())])
            self.assertEqual(str(caught.exception),reason)


    def test_socket_timeout_is_reduced_even_after_connection_close_header(self):
        clock=[100.0]
        self.budget['deadline']=120.0
        timeouts=[]
        class SlowBody(Response):
            def read1(self,count):
                clock[0]+=1
                return super().read1(10)
        status,body=wire(finder())
        def responses(provider):
            provider.sock=None
            return SlowBody(status,body)
        with patch('time.monotonic',side_effect=lambda:clock[0]), \
             patch.object(Provider,'getresponse',responses), \
             patch.object(Socket,'settimeout',side_effect=lambda value:timeouts.append(value)):
            with self.assertRaises(RuntimeError):
                self.run_review([])
        self.assertGreater(len(timeouts),2)
        self.assertLess(timeouts[-1],timeouts[0])


    def test_real_loopback_sockets_close_without_false_transport_error(self):
        import http.client
        pairs=[socket.socketpair() for _ in range(4)]
        pending=iter(pairs)
        for (_,server),(_,body) in zip(pairs,[wire(finder())]+[wire(juror())]*3):
            server.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+
                b'\r\nConnection: close\r\n\r\n'+body)
            server.shutdown(socket.SHUT_WR)
        def connect(connection):
            connection.sock=next(pending)[0]
        try:
            with patch.dict(os.environ,{'OPENCODE_GO_API_KEY':'fixture-only'}), \
                 patch.object(http.client.HTTPSConnection,'connect',connect), \
                 patch.object(socket.socket,'connect',side_effect=AssertionError('OUTBOUND')) as outbound, \
                 patch('socket.getaddrinfo',side_effect=AssertionError('DNS OUTBOUND')):
                result=review(self.manifest,'Approved policy',self.runtime,self.budget,admit=self.admit)
            self.assertEqual(result['execution']['actual_response_count'],4)
            outbound.assert_not_called()
        finally:
            for client,server in pairs:
                client.close()
                server.close()


    def test_invalid_domain_ballot_never_returns_candidate_result(self):
        bad=dict(juror(),votes=[dict(candidate_id='foreign',vote='uncertain',reason='missing evidence',
            anchors=[],evidence_refs=[],counterevidence_refs=[])])
        with self.assertRaises(RuntimeError) as caught:
            self.run_review([wire(finder())]+[wire(bad)]*3)
        self.assertEqual(str(caught.exception),'PROTOCOL_INVALID')


    def test_error_response_is_closed_before_returning_exception(self):
        with self.assertRaises(RuntimeError):
            self.run_review([(503,b'error')])
        self.assertTrue(self.last_provider.response_objects[0].closed)
        self.assertEqual(self.last_provider.closed,1)


if __name__ == '__main__':
    unittest.main()
