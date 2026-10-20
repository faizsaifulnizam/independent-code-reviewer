# Independent Code Reviewer

**Development preview — not qualified for ordinary live use.**

## Observed qualification

An offline issue integration test exercises the actual CLI parser → collector → direct runner → validator → saved `review.json` and `review.md`, replacing GitHub and provider I/O with fakes. Synthetic responses establish artifact delivery, not real defect detection. PR behavior has component tests, not full live PR qualification. The current offline suite passes 74 unittest methods, including 27 ballot combinations as subtests (not additional methods).

Whole-invocation deadline enforcement across DNS, TLS and response-header waits remains unproven. Real GitHub/provider authentication, provider acceptance of requested effort, quota/billing behavior and review accuracy have not been tested. No live inference or accuracy benchmark is claimed.

## Checkout

Prerequisites: Git, Python 3.11+ and GitHub CLI (`gh`) for experimental live acquisition. Python uses only the standard library; no `pip install` is needed. Run these commands from the checkout root; there is no installed console entry point.

```bash
git clone https://github.com/faizsaifulnizam/independent-code-reviewer.git
cd independent-code-reviewer
python -m unittest discover -s tests -p "test_*.py" -v
python -m reviewer.cli --help
python -m reviewer.cli draft --help
```

Use a Python 3.11+ interpreter as `python`, or substitute your platform's launcher. Tests use synthetic boundary I/O and some local loopback sockets, not live AI requests.

Source is hosted on GitHub. The current Actions workflow runs offline tests only; it does not deploy or run an AI service. No extra server, domain or database is required.

An advisory second-opinion reviewer for GitHub pull requests and standalone issues. A finder proposes defects; three fresh model contexts check each candidate; deterministic code validates evidence and tallies a two-of-three decision. The reviewer does not edit source, execute repository scripts, approve/merge PRs, post comments or close issues.

**Development status:** the direct Python draft engine is under construction and qualification. No accuracy or production-readiness claim is made. Automatic intake and comment publication are not enabled. `examples/invoices.py` is synthetic test data, not a real application.

## Design

- Python 3.11+ standard library; GitHub CLI (`gh`) for authenticated, bounded read-only acquisition.
- Direct OpenCode Go requests to `deepseek-v4.1-flash`, requested high effort. No OpenCode coding-agent process, retry, fallback, database, service or vector memory.
- Explicit owner grant read afresh from the control repository default branch before each protected evidence/model operation. Source-controlled PR instructions cannot grant authority.
- At most four finder responses and one per juror, seven scheduled in a run. No missing-juror quorum reduction or re-vote.
- A completed result is an advisory snapshot, not proof the code is bug-free. Partial, blocked, failed, stale and unknown-currentness results remain visible.

## Cost and privacy

The code is MIT-licensed. Standard GitHub-hosted runner computing is free for public workflow repositories; private workflows use plan allowances and may incur overage. Model requests consume the selected existing OpenCode Go allowance. **Disable Go's Use balance option before granting live inference**; client-side no-retry/no-fallback does not disable server-side credit spending. No additional paid service is required by this draft design.

Approved source and discussion text leave the machine for the model provider. This is not offline inference. Provider retention terms must be checked separately. Never put API keys, private source, raw payloads, personal agent history or local run records in Git. Private repositories and fork PRs are unsupported in this initial slice.

## Development checks

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

These are offline tests unless explicitly stated otherwise. Synthetic provider fixtures are not live review results. Do not supply a real model key to an unreviewed test harness.

## Planned ordinary invocation

```bash
python -m reviewer.cli draft --request request.json --output runs/review-001 --control-repository OWNER/REPO
```

The request and active remote grant must agree on repository identity, subject, actor, policy/runtime digests, provider, effort, budget and expiry. Empty `config/repositories.json` grants mean no model work is authorized. `OPENCODE_GO_API_KEY` belongs only in the invoking process environment or the platform's secret store, never a JSON file or committed `.env`. GitHub identity comes from `gh`; credential values are never part of review evidence.

**This invocation is experimental, not a live setup recipe. Keep grants empty until separate qualification and authorization; do not enable model grants on the strength of offline tests.** `--control-repository` must equal the request's source `repository`; separate central control repositories are unsupported. That public source repository must contain the control configuration on its default branch. Replacing `OWNER/REPO` alone is insufficient.

The runtime's `context_paths` names synthetic `examples/invoices.py`. For another project, deliberately configure approved context paths in runtime and grant, then update matching digests. The synthetic file is not application context.

### Request and grant fields

- Request: `schema_version` is `0.2`; `request_id` is a UUID. `repository` is `OWNER/REPO`; `repository_id` and `actor_id` are numeric GitHub identities, with the latter matching authenticated `gh`. `subject_kind` (`issue` or `pull_request`) and positive `subject_number` select the subject. `mode` is `draft`, `trigger` is `manual`, and `grant_id` selects the remote authority record.
- Bindings: `requested_effort`, `policy_digest` and `runtime_digest` must match authorization. Digests are SHA256 over exact bytes of `config/review-policy.md` and `config/runtime.json`.
- Grant: binds the same repository, actor and digests; restricts `subjects`, `modes`, `triggers`, `efforts` and `context_paths`; sets `public_only`, provider/model, `max_responses` and timezone-aware `expires_at`. Absent, disabled, expired or mismatched grants do not authorize work.
- `tests/test_integration.py` demonstrates synthetic fields using boundary fakes. Its enabled in-memory fixture is test-only, not a live grant template. No real identity or key is supplied here.

Use a new output directory and retain the response ledger across attempts; deleting it is not a safe budget reset. Custom request/output/ledger paths are not automatically protected by `.gitignore`.

### Additional limits

The approved Go model scope is `deepseek-v4.1-flash` with requested effort `high` or `max`; shipped runtime uses `high`. An effort change requires deliberate runtime/request/grant updates and matching digests. Jurors use isolated contexts of the same model, not independent providers. No private source or personal data belongs in a trial.

Existing Go allowance is not a zero-cost guarantee: balance/credit spending or overage may occur. **Use balance must be OFF before separately authorized live inference.** `use_balance_off` is an operator declaration, not verification of provider account state; a boolean and client no-retry/no-fallback cannot prove a spending ceiling.

`.gitattributes` enforces `* text eol=lf` so Windows `autocrlf` conversion does not silently alter policy/runtime SHA256 identity. Preserve LF checkout bytes and recompute bindings after intentional configuration edits; do not reuse stale digests.
