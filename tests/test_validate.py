import unittest
from reviewer import validate as v

class Parsing(unittest.TestCase):
    def test_strict_json(self):
        self.assertEqual(v.parse_json('{"a":1}'), {'a':1})
        for raw in ['{"a":1,"a":2}', '[NaN]', '[Infinity]', '[-Infinity]', '{bad}', '"\ud800"']:
            with self.subTest(raw=repr(raw)), self.assertRaises(ValueError):
                v.parse_json(raw)
        with self.assertRaises(ValueError): v.parse_json('{}', max_bytes=1)
        self.assertEqual(v.canonical_digest({'b':2,'a':1}), v.canonical_digest({'a':1,'b':2}))
        with self.assertRaises(ValueError): v.canonical_digest(float('nan'))

class Request(unittest.TestCase):
    def test_request_boundary(self):
        r = request()
        self.assertEqual(v.check_request(r), r)
        for field, value in [('repository_id', True), ('subject_number', 0), ('repository', '../x'), ('request_id', 'bad'), ('policy_digest', 'A'*64), ('mode', 'publish'), ('requested_effort','low')]:
            with self.subTest(field=field), self.assertRaises(ValueError): v.check_request(dict(r, **{field:value}))

def request():
    return dict(schema_version='0.2', request_id='12345678-1234-4234-8234-123456789012', repository_id=1, repository='owner/repo', subject_kind='pull_request', subject_number=2, mode='draft', trigger='manual', actor_id=3, grant_id='grant', policy_digest='a'*64, runtime_digest='b'*64, requested_effort='high')

def panel(votes=('supported',)*3, ids=('C1',)):
    entry = dict(evidence_id='E1', path='src/a.py', blob_digest='c'*64, line_count=2)
    anchor = dict(evidence_id='E1',path='src/a.py',blob_digest='c'*64,start_line=1,end_line=2)
    identity = dict(run_id=request()['request_id'],candidate_batch_digest='d'*64,evidence_digest='e'*64,policy_digest='a'*64,runtime_digest='b'*64,entries=[entry],response_receipts=[])
    batches=[]
    for i, vote in enumerate(votes,1):
        slot='J'+str(i)
        identity['response_receipts'].append(dict(id=slot,slot=slot,attempt_id='a'+str(i),status='completed'))
        batch={k:identity[k] for k in ('run_id','candidate_batch_digest','evidence_digest','policy_digest','runtime_digest')}
        batch.update(schema_version='0.2',juror_id=slot,response_receipt_id=slot,scope_complete=True,scope_evidence_refs=['E1'],assessment_agreement=None,late_candidates=[],votes=[dict(candidate_id=c,vote=vote,reason='Evidence supports this assessment',anchors=[dict(anchor)],evidence_refs=['E1'],counterevidence_refs=[],trigger='input',mechanism='branch',impact='failure') for c in ids])
        batches.append(batch)
    return batches,identity

class Jury(unittest.TestCase):
    def test_all_27(self):
        import itertools
        for votes in itertools.product(('supported','refuted','uncertain'), repeat=3):
            with self.subTest(votes=votes):
                batches,identity=panel(votes)
                result=v.tally_jury(['C1'],batches,identity)[0]
                expected='accepted' if votes.count('supported')>=2 else 'rejected' if votes.count('refuted')>=2 else 'unresolved'
                self.assertEqual(result['decision'],expected)
                self.assertEqual(result['threshold'],2)
                self.assertEqual(len(result['ballots']),3)
    def test_invalid_panels(self):
        import copy
        for index in range(3):
            b,e=panel()
            with self.assertRaises(ValueError): v.tally_jury(['C1'],b[:index]+b[index+1:],e)
        mutations=[lambda b,e:b[2].update(juror_id='J1'),lambda b,e:b[0].update(juror_id='finder'),lambda b,e:b[0].update(evidence_digest='f'*64),lambda b,e:b[0].update(response_receipt_id='J2'),lambda b,e:b[0]['votes'][0].update(candidate_id='foreign'),lambda b,e:b[0]['votes'].append(copy.deepcopy(b[0]['votes'][0])),lambda b,e:b[0]['votes'][0]['anchors'][0].update(start_line=True),lambda b,e:b[0]['votes'][0]['anchors'][0].update(end_line=3),lambda b,e:b[0]['votes'][0]['anchors'][0].update(path='../a.py'),lambda b,e:b[0]['votes'][0].update(anchors=[]),lambda b,e:b[0].update(scope_complete=1)]
        for mutate in mutations:
            b,e=panel();mutate(b,e)
            with self.assertRaises(ValueError): v.tally_jury(['C1'],b,e)
    def test_duplicate_attempts_and_bad_paths(self):
        for bad in ('src/line\nfile.py','src/a\t.py','src/a\\b.py','src/a:stream','src//a.py','./a.py'):
            b,e=panel()
            e['entries'][0]['path']=bad
            for batch in b:batch['votes'][0]['anchors'][0]['path']=bad
            with self.subTest(path=repr(bad)),self.assertRaises(ValueError):v.tally_jury(['C1'],b,e)
        b,e=panel();e['response_receipts'][1]['attempt_id']=e['response_receipts'][0]['attempt_id']
        with self.assertRaises(ValueError):v.tally_jury(['C1'],b,e)
    def test_uncertain_without_anchor_is_valid(self):
        b,e=panel(('uncertain',)*3)
        for batch in b:batch['votes'][0].update(anchors=[],evidence_refs=[],reason='Required counterexample is missing')
        self.assertEqual(v.tally_jury(['C1'],b,e)[0]['decision'],'unresolved')
    def test_empty_still_requires_panel(self):
        b,e=panel(ids=())
        self.assertEqual(v.tally_jury([],b,e),[])
        with self.assertRaises(ValueError): v.tally_jury([],b[:2],e)

def fixture(empty=False, issue=False):
    r=request()
    if issue:r['subject_kind']='issue'
    b,e=panel(ids=() if empty else ('C1',))
    entry=dict(e['entries'][0],kind='context_source',text='a\nb\n',byte_count=4,provenance='source',disposition='required',reason='scope')
    import hashlib
    entry['blob_digest']=hashlib.sha256(entry['text'].encode()).hexdigest()
    m={k:r[k] for k in ('request_id','repository_id','repository','subject_kind','subject_number','policy_digest','runtime_digest')}
    m.update(complete=True,pages_fetched=1,pages_expected=1,entries=[entry],thread_digest='c'*64)
    m.update({'repository_oid':'f'*40} if issue else {'base_oid':'f'*40,'head_oid':'e'*40})
    m['evidence_digest']=v.canonical_digest(m)
    candidate=dict(candidate_id='C1',severity='high',confidence='high',title='Defect',trigger='input',mechanism='branch',impact='failure',anchors=[dict(b[0]['votes'][0]['anchors'][0],blob_digest=entry['blob_digest'])] if not empty else [],evidence_class='reasoned_path',evidence_refs=['E1'],verification_step=dict(description='Check the input',status='not_run'))
    candidates=[] if empty else [candidate]
    digest=v.canonical_digest(candidates)
    for batch in b:
        batch.update(candidate_batch_digest=digest,evidence_digest=m['evidence_digest'],assessment_agreement='agree' if issue else None)
        for vote in batch['votes']:vote['anchors'][0]['blob_digest']=entry['blob_digest']
    result=dict(run_id=e['run_id'],candidates=candidates,candidate_batch_digest=digest,issue_assessment=dict(conclusion='needs_evidence',claims=[],missing_information=[],reproduction_status='not_run') if issue else None,summary='Advisory snapshot',missing_evidence=[],juror_batches=b,execution=dict(response_receipts=e['response_receipts'],actual_response_count=3,requested_provider='opencode-go',requested_model='deepseek-v4.1-flash',requested_effort='high',observed_provider=None,observed_model=None,observed_effort=None,checkpoint=None,uncertain_attempts=0,wall_time_s=1,configured_caps={},stop_reason=None),read_receipts=[dict(evidence_id='E1',start_line=1,end_line=2,admission=dict(allowed=True))])
    return r,m,result,dict(currentness='current',authorized=True)

class Artifact(unittest.TestCase):
    def test_snapshot_and_caps_retained(self):
        r,m,c,l=fixture();c['execution']['configured_caps']={'max_responses':7}
        a=v.validate(r,m,c,l)
        self.assertEqual(a['thread_digest'],m['thread_digest'])
        self.assertEqual(a['execution']['configured_caps'],{'max_responses':7})
    def test_execution_metadata_cannot_smuggle_payloads(self):
        for field,value in [('observed_model',{'raw':'source'}),('wall_time_s',True),('requested_effort','low'),('actual_response_count',True)]:
            r,m,c,l=fixture();c['execution'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):v.validate(r,m,c,l)
    def test_empty_panel_retains_packet_identity_and_audits(self):
        r,m,c,l=fixture(empty=True)
        a=v.validate(r,m,c,l)
        for key in ('run_id','candidate_batch_digest','evidence_digest','policy_digest','runtime_digest'):
            self.assertEqual(a['jury_panel'][key],c[key] if key in c else m[key])
        self.assertEqual(len(a['jury_panel']['slots']),3)
    def test_completed_and_empty_issue(self):
        a=v.validate(*fixture())
        self.assertEqual(a['outcome'],'completed_with_findings')
        self.assertTrue(a['jury_panel']['panel_valid'])
        self.assertNotIn('text',str(a['coverage']))
        self.assertNotIn('Evidence supports',str(a))
        self.assertEqual(v.validate(*fixture(empty=True,issue=True))['outcome'],'completed_with_none')
    def test_partial_gates(self):
        for cause in ('low','missing','scope','late','coverage','disagreement','unresolved'):
            r,m,c,l=fixture(issue=cause=='disagreement')
            if cause=='low':c['candidates'][0]['confidence']='low'
            if cause=='missing':c['missing_evidence']=['gap']
            if cause=='scope':c['juror_batches'][0]['scope_complete']=False
            if cause=='late':c['juror_batches'][0]['late_candidates']=[{'title':'unadjudicated'}]
            if cause=='coverage':c['read_receipts']=[]
            if cause=='disagreement':c['juror_batches'][0]['assessment_agreement']='uncertain'
            if cause=='unresolved':
                for b,vote in zip(c['juror_batches'],('supported','refuted','uncertain')):b['votes'][0]['vote']=vote
            if cause=='low':
                c['candidate_batch_digest']=v.canonical_digest(c['candidates'])
                for b in c['juror_batches']:b['candidate_batch_digest']=c['candidate_batch_digest']
            with self.subTest(cause=cause):self.assertEqual(v.validate(r,m,c,l)['outcome'],'partial')
    def test_unknown_currentness_is_partial(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                r,m,c,l=fixture(empty=empty);l['currentness']='unknown'
                a=v.validate(r,m,c,l)
                self.assertEqual(a['outcome'],'partial')
                self.assertEqual(a['currentness'],'unknown')
                self.assertEqual(a['limitations'],['CURRENTNESS_UNKNOWN'])
                self.assertEqual(len(a['findings']),0 if empty else 1)
    def test_currentness_authority_precedence(self):
        for empty in (False, True):
            for currentness in ('current','unknown','stale'):
                for authorized in (False, True):
                    with self.subTest(empty=empty,currentness=currentness,authorized=authorized):
                        r,m,c,l=fixture(empty=empty)
                        l.update(currentness=currentness,authorized=authorized)
                        a=v.validate(r,m,c,l)
                        expected=('stale' if currentness=='stale' else 'blocked' if not authorized else 'partial' if currentness=='unknown' else 'completed_with_none' if empty else 'completed_with_findings')
                        self.assertEqual(a['outcome'],expected)
                        self.assertEqual(a['currentness'],currentness)
                        self.assertEqual('NOT_AUTHORIZED' in a['limitations'],not authorized)
                        self.assertEqual('CURRENTNESS_UNKNOWN' in a['limitations'],currentness=='unknown')
                        self.assertEqual('SUBJECT_CHANGED' in a['limitations'],currentness=='stale')
    def test_authority_and_staleness(self):
        r,m,c,l=fixture();l['authorized']=False
        self.assertEqual(v.validate(r,m,c,l)['outcome'],'blocked')
        l['currentness']='stale'
        self.assertEqual(v.validate(r,m,c,l)['outcome'],'stale')
    def test_forged_evidence_and_execution(self):
        for cause in ('text','executed','read','candidate_digest','issue'):
            r,m,c,l=fixture()
            if cause=='text':m['entries'][0]['text']='forged'
            if cause=='executed':c['candidates'][0]['evidence_class']='executed_reproduction'
            if cause=='read':c['read_receipts'][0]['admission']['allowed']=1
            if cause=='candidate_digest':c['candidate_batch_digest']='f'*64
            if cause=='issue':c['issue_assessment']={}
            with self.subTest(cause=cause),self.assertRaises(ValueError):v.validate(r,m,c,l)
    def test_malformed_nested_values_are_value_errors(self):
        mutations=[lambda r,m,c,l:c['juror_batches'][0]['votes'][0].update(candidate_id=[]),lambda r,m,c,l:c['juror_batches'][0]['votes'][0]['anchors'][0].update(evidence_id=[]),lambda r,m,c,l:c['juror_batches'][0].update(juror_id=[]),lambda r,m,c,l:m.update(repository_id=True),lambda r,m,c,l:c['execution'].update(response_receipts=[{}]),lambda r,m,c,l:c['issue_assessment'].update(claims=[{'evil':'invented'}])]
        for mutate in mutations:
            r,m,c,l=fixture(issue=True);mutate(r,m,c,l)
            m['evidence_digest']=v.canonical_digest({k:x for k,x in m.items() if k!='evidence_digest'})
            for b in c['juror_batches']:b['evidence_digest']=m['evidence_digest']
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):v.validate(r,m,c,l)
    def test_candidate_summary_retained_without_raw_reasoning(self):
        r,m,c,l=fixture()
        a=v.validate(r,m,c,l)
        self.assertEqual(a['findings'][0]['trigger'],'input')
        self.assertEqual(a['findings'][0]['mechanism'],'branch')
        self.assertEqual(a['findings'][0]['impact'],'failure')
    def test_renderer_is_bounded_advisory_not_model_commands(self):
        a=v.validate(*fixture())
        a['summary']='@everyone ![x](https://evil.test/x) <script> /approve C:/private/key\x00'
        a['findings'][0]['title']='Run rm -rf / now @user'
        text=v.render_markdown(a)
        self.assertLessEqual(len(text),20000)
        for forbidden in ('@','https://','<script>','C:/','rm -rf','\x00'):self.assertNotIn(forbidden,text)
        self.assertIn('not run',text.lower())

if __name__ == '__main__': unittest.main()
