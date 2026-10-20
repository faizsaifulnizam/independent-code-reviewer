"""Authoritative strict validation for the bounded draft reviewer."""
import hashlib
import json
import re
import uuid


def parse_json(raw, max_bytes=1048576):
    try:
        data = raw.encode('utf-8') if isinstance(raw, str) else raw
        if not isinstance(data, bytes) or len(data) > max_bytes:
            raise ValueError('PROTOCOL_INVALID')
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError('PROTOCOL_INVALID')
                result[key] = value
            return result
        result = json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('PROTOCOL_INVALID')))
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode('utf-8')
        return result
    except (UnicodeError, TypeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError('PROTOCOL_INVALID') from exc


def _require(condition, reason='PROTOCOL_INVALID'):
    if not condition: raise ValueError(reason)


def _text(value):
    _require(isinstance(value, str) and 0 < len(value) <= 20000 and not any(ord(c) < 32 and c not in '\n\t' for c in value))


def _digest(value):
    _require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None)


def _positive(value):
    _require(type(value) is int and value > 0)


def _path(value):
    _text(value)
    _require(not any(ord(c)<32 or ord(c)==127 for c in value))
    _require(not value.startswith('/') and not any(c in value for c in '\\:\\?*<>|') and all(p not in ('', '.', '..') for p in value.split('/')))


def _uuid(value):
    _require(isinstance(value, str))
    try: _require(str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError): raise ValueError('PROTOCOL_INVALID')


def check_request(request):
    fields = 'schema_version request_id repository_id repository subject_kind subject_number mode trigger actor_id grant_id policy_digest runtime_digest requested_effort'.split()
    _require(type(request) is dict and set(request) == set(fields))
    _require(request['schema_version'] == '0.2' and request['mode'] == 'draft')
    _uuid(request['request_id'])
    for key in ('repository_id', 'subject_number', 'actor_id'): _positive(request[key])
    _require(isinstance(request['repository'], str) and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}', request['repository']) is not None)
    _require(request['repository'].split('/')[1] not in ('.', '..'))
    _require(request['subject_kind'] in ('pull_request', 'issue'))
    _require(request['trigger'] in ('manual', 'pr_event', 'issue_event', 'approved_comment'))
    _require(request['requested_effort'] in ('high', 'max'))
    _require(isinstance(request['grant_id'], str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', request['grant_id']) is not None)
    for key in ('policy_digest', 'runtime_digest'): _digest(request[key])
    return request


def _refs(refs, entries):
    _require(type(refs) is list and all(isinstance(x, str) for x in refs))
    _require(len(refs) == len(set(refs)) and set(refs) <= set(entries))


def _anchors(anchors, entries):
    _require(type(anchors) is list)
    for a in anchors:
        _require(type(a) is dict)
        entry = entries.get(a.get('evidence_id'))
        _require(entry is not None, 'ANCHOR_INVALID')
        location = 'path' if 'path' in entry else 'issue_object_id'
        _require(set(a) == {'evidence_id', location, 'blob_digest', 'start_line', 'end_line'}, 'ANCHOR_INVALID')
        _require(a[location] == entry[location] and a['blob_digest'] == entry['blob_digest'], 'ANCHOR_INVALID')
        if location == 'path': _path(a[location])
        _require(type(a['start_line']) is int and type(a['end_line']) is int and 1 <= a['start_line'] <= a['end_line'] <= entry['line_count'], 'ANCHOR_INVALID')


def tally_jury(candidate_ids, juror_batches, expected_identity):
    try:
        return _tally_jury(candidate_ids, juror_batches, expected_identity)
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeError) as exc:
        raise ValueError('BALLOT_INVALID') from exc


def _tally_jury(candidate_ids, juror_batches, expected_identity):
    _require(type(candidate_ids) is list and all(isinstance(c, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', c) for c in candidate_ids))
    _require(len(set(candidate_ids)) == len(candidate_ids))
    _require(type(juror_batches) is list and len(juror_batches) == 3, 'JUROR_MISSING')
    identity_fields = ('run_id', 'candidate_batch_digest', 'evidence_digest', 'policy_digest', 'runtime_digest')
    _uuid(expected_identity['run_id'])
    for key in identity_fields[1:]: _digest(expected_identity[key])
    entries = {e['evidence_id']:e for e in expected_identity['entries']}
    _require(len(entries) == len(expected_identity['entries']))
    receipts = expected_identity['response_receipts']
    _require(type(receipts) is list and all(type(r) is dict and isinstance(r.get('id'),str) and isinstance(r.get('attempt_id'),str) and bool(r['attempt_id']) for r in receipts))
    _require(len({r['id'] for r in receipts}) == len(receipts) and len({r['attempt_id'] for r in receipts}) == len(receipts))
    by_receipt = {r['id']:r for r in receipts}
    _require({b.get('juror_id') for b in juror_batches} == {'J1','J2','J3'}, 'BALLOT_INVALID')
    fields = set(identity_fields) | {'schema_version','juror_id','scope_complete','scope_evidence_refs','assessment_agreement','votes','late_candidates','response_receipt_id'}
    collected = {c:[] for c in candidate_ids}
    for batch in sorted(juror_batches, key=lambda b:b['juror_id']):
        _require(set(batch) == fields and batch['schema_version'] == '0.2', 'BALLOT_INVALID')
        _require(all(batch[k] == expected_identity[k] for k in identity_fields), 'BALLOT_INVALID')
        receipt = by_receipt.get(batch['response_receipt_id'])
        _require(receipt is not None and receipt.get('slot') == batch['juror_id'] and receipt.get('status') == 'completed' and isinstance(receipt.get('attempt_id'), str), 'BALLOT_INVALID')
        _require(sum(r.get('slot') == batch['juror_id'] for r in receipts) == 1, 'BALLOT_INVALID')
        _require(type(batch['scope_complete']) is bool and batch['assessment_agreement'] in (None,'agree','uncertain','disagree'))
        _refs(batch['scope_evidence_refs'], entries)
        _require(type(batch['late_candidates']) is list)
        _require(type(batch['votes']) is list and len(batch['votes']) == len(candidate_ids))
        seen = set()
        for vote in batch['votes']:
            required = {'candidate_id','vote','reason','anchors','evidence_refs','counterevidence_refs'}
            _require(type(vote) is dict and required <= set(vote) and set(vote) <= required | {'trigger','mechanism','impact'}, 'BALLOT_INVALID')
            cid=vote['candidate_id']
            _require(cid in collected and cid not in seen, 'BALLOT_INVALID'); seen.add(cid)
            _require(vote['vote'] in ('supported','refuted','uncertain'))
            _text(vote['reason']); _anchors(vote['anchors'], entries)
            _refs(vote['evidence_refs'], entries); _refs(vote['counterevidence_refs'], entries)
            if vote['vote'] != 'uncertain':
                _require(bool(vote['anchors']) and bool(vote['evidence_refs']))
            _require(all(a['evidence_id'] in vote['evidence_refs'] + vote['counterevidence_refs'] for a in vote['anchors']))
            if vote['vote'] == 'supported':
                for key in ('trigger','mechanism','impact'): _text(vote.get(key))
            collected[cid].append(dict(juror_id=batch['juror_id'],response_receipt_id=batch['response_receipt_id'],vote=vote['vote'],evidence_refs=list(vote['evidence_refs']),counterevidence_refs=list(vote['counterevidence_refs']),anchors=vote['anchors']))
    results=[]
    for cid, ballots in collected.items():
        counts={k:sum(b['vote']==k for b in ballots) for k in ('supported','refuted','uncertain')}
        decision='accepted' if counts['supported']>=2 else 'rejected' if counts['refuted']>=2 else 'unresolved'
        majority='supported' if decision=='accepted' else 'refuted' if decision=='rejected' else None
        result={k:expected_identity[k] for k in identity_fields}
        result.update(candidate_id=cid,ballots=ballots,counts=counts,threshold=2,decision=decision,dissent=[b['juror_id'] for b in ballots if b['vote']!=majority],validation_errors=[])
        results.append(result)
    return results


def _candidate(candidate, entries):
    required=set('candidate_id severity confidence title trigger mechanism impact anchors evidence_class evidence_refs verification_step'.split())
    _require(type(candidate) is dict and required <= set(candidate) <= required | {'finding_id'})
    for key in ('candidate_id','finding_id'):
        if key in candidate: _require(isinstance(candidate[key],str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',candidate[key]) is not None)
    _require(candidate['severity'] in ('critical','high','medium','low') and candidate['confidence'] in ('high','medium','low'))
    for key in ('title','trigger','mechanism','impact'): _text(candidate[key])
    _require(candidate['evidence_class'] in ('reasoned_path','existing_test_or_log'))
    _anchors(candidate['anchors'],entries); _refs(candidate['evidence_refs'],entries)
    _require(bool(candidate['anchors']) and all(a['evidence_id'] in candidate['evidence_refs'] for a in candidate['anchors']))
    if candidate['evidence_class']=='existing_test_or_log':
        _require(any(entries[r]['kind'] in ('existing_test','existing_log') for r in candidate['evidence_refs']))
    step=candidate['verification_step']
    _require(type(step) is dict and set(step)=={'description','status'} and step['status']=='not_run')
    _text(step['description'])


def validate(request, manifest, candidate_result, live_state):
    try:
        return _validate(request, manifest, candidate_result, live_state)
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeError) as exc:
        raise ValueError('PROTOCOL_INVALID') from exc


def _safe_prose(value):
    _text(value)
    # Retain the concise hypothesis, never URLs, mentions, host paths or commands.
    if re.search(r'https?://|www\.|@|[<>]|!\[|[A-Za-z]:[/\\\\]|(?:^|\s)/[A-Za-z]|`|\b(?:curl|wget|powershell|cmd\.exe|rm\s+-|sudo|eval|exec)\b',value,re.I):
        return '[Unsafe advisory text omitted]'
    return value[:1000]


def _validate(request, manifest, candidate_result, live_state):
    check_request(request)
    # Round-trip enforces finite JSON values and no non-JSON runtime objects.
    canonical_digest(manifest); canonical_digest(candidate_result)
    _require(type(manifest) is dict and type(candidate_result) is dict and type(live_state) is dict)
    for key in ('request_id','repository_id','repository','subject_kind','subject_number','policy_digest','runtime_digest'):
        _require(type(manifest.get(key)) is type(request[key]) and manifest.get(key)==request[key])
    _digest(manifest.get('evidence_digest')); _digest(manifest.get('thread_digest'))
    _require(canonical_digest({k:x for k,x in manifest.items() if k!='evidence_digest'})==manifest['evidence_digest'])
    snapshot_keys=('base_oid','head_oid') if request['subject_kind']=='pull_request' else ('repository_oid',)
    for key in snapshot_keys: _require(isinstance(manifest.get(key),str) and re.fullmatch('[0-9a-f]{40}',manifest[key]) is not None)
    _require(type(manifest.get('complete')) is bool)
    _require(type(manifest.get('pages_fetched')) is int and manifest['pages_fetched']>=0)
    _require(manifest.get('pages_expected') is None or (type(manifest['pages_expected']) is int and manifest['pages_expected']>=0))
    _require(type(manifest.get('entries')) is list)
    entries={}
    for entry in manifest['entries']:
        _require(type(entry) is dict)
        eid=entry.get('evidence_id')
        _require(isinstance(eid,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',eid) is not None and eid not in entries)
        _require(entry.get('kind') in ('changed_source','context_source','issue_body','issue_comment','requirement','existing_test','existing_log'))
        _require(entry.get('disposition') in ('required','excluded','missing','truncated','withheld'))
        _require(entry.get('provenance') in ('source','author_claim','later_evidence','trusted_policy'))
        _require(('path' in entry) != ('issue_object_id' in entry))
        if 'path' in entry: _path(entry['path'])
        else: _positive(entry['issue_object_id'])
        _digest(entry.get('blob_digest'))
        _require(type(entry.get('line_count')) is int and entry['line_count']>=0 and type(entry.get('byte_count')) is int and entry['byte_count']>=0)
        text=entry.get('text')
        _require(isinstance(text,str))
        data=text.encode('utf-8')
        _require(len(data)==entry['byte_count'] and len(text.splitlines())==entry['line_count'])
        _require(hashlib.sha256(data).hexdigest()==entry['blob_digest'])
        if 'source_oid' in entry: _require(re.fullmatch('[0-9a-f]{40}',entry['source_oid']) is not None)
        entries[eid]=entry
    result=candidate_result
    _uuid(result.get('run_id'))
    _require(type(result.get('candidates')) is list)
    candidates=result['candidates']
    for c in candidates:_candidate(c,entries)
    _require(result.get('candidate_batch_digest')==canonical_digest(candidates))
    _require(type(result.get('missing_evidence')) is list)
    _text(result.get('summary'))
    execution=result.get('execution')
    _require(type(execution) is dict and type(execution.get('response_receipts')) is list)
    receipts=execution['response_receipts']
    _require(execution.get('requested_provider')=='opencode-go' and execution.get('requested_model')=='deepseek-v4.1-flash' and execution.get('requested_effort')==request['requested_effort'])
    for key in ('observed_provider','observed_model','observed_effort','checkpoint','stop_reason'):
        value=execution.get(key)
        _require(value is None or (isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}',value) is not None))
    _require(execution.get('observed_effort') in (None,'high','max'))
    _require(type(execution.get('wall_time_s')) in (int,float) and 0<=execution['wall_time_s']<=900)
    _require(type(execution.get('configured_caps')) is dict and all(isinstance(k,str) and type(x) in (int,float) and x>=0 for k,x in execution['configured_caps'].items()))
    _require(type(execution.get('actual_response_count')) is int and 3<=execution['actual_response_count']<=7)
    _require(type(execution.get('uncertain_attempts')) is int and execution['uncertain_attempts']>=0)
    identity={k:manifest[k] for k in ('evidence_digest','policy_digest','runtime_digest')}
    identity.update(run_id=result['run_id'],candidate_batch_digest=result['candidate_batch_digest'],entries=manifest['entries'],response_receipts=receipts)
    decisions=tally_jury([c['candidate_id'] for c in candidates],result.get('juror_batches'),identity)
    assessment=result.get('issue_assessment')
    if request['subject_kind']=='pull_request': _require(assessment is None)
    else:
        _require(type(assessment) is dict and set(assessment)=={'conclusion','claims','missing_information','reproduction_status'})
        _require(assessment['conclusion'] in ('supported','contradicted','needs_evidence','needs_investigation'))
        _require(type(assessment['claims']) is list and type(assessment['missing_information']) is list)
        for claim in assessment['claims']:
            _require(type(claim) is dict and set(claim)=={'claim','evidence_refs','counterevidence_refs'})
            _text(claim['claim']); _refs(claim['evidence_refs'],entries); _refs(claim['counterevidence_refs'],entries)
        for missing in assessment['missing_information']:_text(missing)
        _require(assessment['reproduction_status'] in ('not_run','existing_evidence'))
        if assessment['reproduction_status']=='existing_evidence': _require(any(e['kind'] in ('existing_test','existing_log') for e in entries.values()))
    ranges={eid:[] for eid in entries}
    reads=result.get('read_receipts')
    _require(type(reads) is list)
    for read in reads:
        _require(type(read) is dict and read.get('evidence_id') in entries)
        entry=entries[read['evidence_id']]
        start,end=read.get('start_line'),read.get('end_line')
        _require(type(start) is int and type(end) is int and 1<=start<=end<=entry['line_count'])
        _require(type(read.get('admission')) is dict and read['admission'].get('allowed') is True)
        _require(len(''.join(entry['text'].splitlines(keepends=True)[start-1:end]).encode('utf-8'))<=65536)
        ranges[read['evidence_id']].append((start,end))
    required_complete=True
    for eid,entry in entries.items():
        if entry['disposition']!='required':continue
        upto=0
        for start,end in sorted(ranges[eid]):
            if start>upto+1:break
            upto=max(upto,end)
        if upto<entry['line_count']:required_complete=False
    limitations=[]
    if not required_complete:limitations.append('MISSING_EVIDENCE')
    if not manifest['complete'] or manifest['pages_expected'] is None or manifest['pages_fetched']!=manifest['pages_expected']:limitations.append('CONTEXT_TRUNCATED')
    gaps=[dict(evidence_id=eid,disposition=e['disposition'],reason='Scoped evidence unavailable or excluded') for eid,e in entries.items() if e['disposition']!='required']
    if any(e['disposition'] in ('missing','truncated','withheld') for e in entries.values()) or result['missing_evidence']:limitations.append('MISSING_EVIDENCE')
    batches=result['juror_batches']
    if any(not b['scope_complete'] for b in batches):limitations.append('CONTEXT_TRUNCATED')
    if any(b['late_candidates'] for b in batches):limitations.append('LATE_CANDIDATE')
    if request['subject_kind']=='issue':
        if any(b['assessment_agreement']!='agree' for b in batches):limitations.append('ASSESSMENT_DISAGREEMENT')
    else:_require(all(b['assessment_agreement'] is None for b in batches))
    findings=[]
    for c,d in zip(candidates,decisions):
        if d['decision']=='unresolved':limitations.append('JURY_UNRESOLVED')
        if d['decision']=='accepted':
            if c['confidence']=='low':limitations.append('LOW_CONFIDENCE')
            else:
                # Only bounded hypothesis prose survives; raw source and ballot reasons do not.
                findings.append(dict(finding_id=c.get('finding_id',c['candidate_id']),candidate_id=c['candidate_id'],severity=c['severity'],confidence=c['confidence'],title=_safe_prose(c['title']),trigger=_safe_prose(c['trigger']),mechanism=_safe_prose(c['mechanism']),impact=_safe_prose(c['impact']),anchors=c['anchors'],evidence_class=c['evidence_class'],evidence_refs=c['evidence_refs'],verification_step=dict(description='Independently verify the anchored candidate.',status='not_run'),jury=d))
    _require(live_state.get('currentness') in ('current','stale','unknown') and type(live_state.get('authorized')) is bool)
    if live_state['currentness']=='unknown':limitations.append('CURRENTNESS_UNKNOWN')
    outcome='partial' if limitations else 'completed_with_findings' if findings else 'completed_with_none'
    if not live_state['authorized']:outcome='blocked';limitations.append('NOT_AUTHORIZED')
    if live_state['currentness']=='stale':outcome='stale';limitations.append('SUBJECT_CHANGED')
    if gaps:limitations.append('SCOPED_EXCLUSIONS')
    safe_execution={k:execution.get(k) for k in ('requested_provider','requested_model','requested_effort','observed_provider','observed_model','observed_effort','checkpoint','actual_response_count','uncertain_attempts','wall_time_s','stop_reason')}
    safe_execution['response_receipts']=[{k:r.get(k) for k in ('id','slot','attempt_id','status')} for r in receipts]
    artifact={k:request[k] for k in ('request_id','repository_id','subject_kind','subject_number','policy_digest','runtime_digest')}
    artifact.update({k:manifest[k] for k in snapshot_keys})
    artifact.update(schema_version='0.2',run_id=result['run_id'],evidence_digest=manifest['evidence_digest'],outcome=outcome,currentness=live_state['currentness'],summary='Advisory snapshot review; source was not executed.',coverage=dict(inspected=[dict(evidence_id=eid,ranges=[list(x) for x in rr]) for eid,rr in ranges.items() if rr],gaps=gaps,required_scope_complete=required_complete,full_collection=manifest['complete']),findings=findings,issue_assessment=None if assessment is None else dict(conclusion=assessment['conclusion'],claims=[],missing_information=['Additional independent verification may be needed.'] if assessment['missing_information'] else [],reproduction_status=assessment['reproduction_status']),execution=safe_execution,jury_panel=dict(panel_valid=True,validation_errors=[],decisions=decisions,slots=[dict(juror_id=b['juror_id'],response_receipt_id=b['response_receipt_id'],scope_complete=b['scope_complete'],scope_evidence_refs=b['scope_evidence_refs'],assessment_agreement=b['assessment_agreement'],late_candidate_count=len(b['late_candidates'])) for b in batches]),limitations=list(dict.fromkeys(limitations)),reused=False)
    artifact['thread_digest']=manifest['thread_digest']
    artifact['execution']['configured_caps']=dict(execution['configured_caps'])
    artifact['jury_panel'].update({k:identity[k] for k in ('run_id','candidate_batch_digest','evidence_digest','policy_digest','runtime_digest')})
    return artifact


def render_markdown(artifact):
    """Fixed prose only: model content cannot become a command, mention or link."""
    allowed=('completed_with_findings','completed_with_none','partial','blocked','failed','stale','skipped')
    _require(artifact.get('outcome') in allowed)
    lines=['# Advisory review draft', '', 'Outcome: '+artifact['outcome'], '', 'Source was not executed. Verification steps were not run.', 'This is not an approval or a claim that the source is safe.', '']
    for index,finding in enumerate(artifact.get('findings',[])[:10],1):
        _require(finding.get('severity') in ('critical','high','medium','low'))
        lines.append(f"- Candidate {index}: {finding['severity']} severity; independently verify the retained source anchors.")
    if artifact.get('limitations'):lines.append('\nLimitations apply; consult the sanitized local artifact.')
    return '\n'.join(lines)[:20000]+'\n'


def canonical_digest(value):
    try:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                        ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()
    except (TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError('PROTOCOL_INVALID') from exc
