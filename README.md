# Carylle

Endpoint detection and response that uses an LLM for judgement and deterministic code for
authority. Agents watch processes, files and network activity on your hosts. The server triages
that telemetry with rules, asks Claude to assess what looks suspicious, and contains threats
within strict guardrails.

The core design decision: **the model reads text written by attackers, so it's never trusted with
authority.** It can explain and prioritize, and it can recommend containment for something it
observed. It can't name an arbitrary target, clear what the rules detected, or cause an unattended
action by itself. [SECURITY.md](SECURITY.md) has the full threat model.

## How it works

```
 ENDPOINT                              SERVER
┌───────────────────────┐             ┌──────────────────────────────────────────────┐
│ process_monitor       │   events    │ normalizer     validate, bound, stamp identity│
│ file_watcher + YARA   │ ──────────► │      │                                       │
│ network_sniffer       │   HTTPS     │ fallback_scorer  deterministic rules          │
│                       │             │      │ nothing flagged: stop, no model cost   │
│ transport             │             │ sanitizer      redact secrets, flag injection │
│  (spools when offline)│             │      │                                       │
│                       │             │ llm_client     Claude, optional               │
│                       │             │      │ any failure: use the rules' verdict    │
│                       │             │ verdict_validator  bind to evidence, floor    │
│                       │             │      │                                       │
│ commands              │   signed    │ orchestrator   playbook + evidence = target   │
│  verify, then act     │ ◄────────── │ guardrails     safelist, mode, rate limits    │
│ process_terminator    │  commands   │ action_ledger  tamper-evident audit trail     │
│ file_quarantine       │             │                                               │
└───────────────────────┘             └──────────────────────────────────────────────┘
```

What happens to an action depends on the response mode, set per server:

| Mode | Behaviour |
|---|---|
| `observe` | Records what would have happened and changes nothing. Also works as the kill switch |
| `approve` | Every endpoint action waits for an operator. **This is the default** |
| `autonomous` | Actions that pass every guardrail run unattended. The rest wait for an operator |

Agents also ship with `actuators_enabled: false`, so a fresh install can observe but can't act.

## Quick start

Needs Python 3.11 or newer.

```sh
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[server,agent-full,dev]"
pytest

carylle-admin init-env > .env    # generates all secrets
set -a; source .env; set +a      # Windows: load these into your environment another way
carylle-server                   # on 127.0.0.1:8443, plain HTTP on loopback only
```

The server works without an API key, using the deterministic scorer for every case. To add Claude,
set `ANTHROPIC_API_KEY`.

### Try it in the isolated lab

The lab runs the server and a victim container on a network with no route out. It's the safe way
to see real detection and response, since the decoys it launches are meant to be killed.

```sh
carylle-admin init-env --lab > .env.lab
docker compose --env-file .env.lab -f docker-compose.lab.yml up -d --build

# Crafted telemetry against the server (nothing executes)
docker compose --env-file .env.lab -f docker-compose.lab.yml run --rm purple

# Harmless decoys against the real agent
docker compose --env-file .env.lab -f docker-compose.lab.yml exec victim \
    python -m purple.runner --mode live --server http://server:8443 --report /tmp/purple-live

docker compose --env-file .env.lab -f docker-compose.lab.yml down -v
```

With `make` available, the same steps are `make lab-env lab-up lab-purple lab-purple-live lab-down`.

## Deploying

**Server:**

```sh
carylle-admin init-env > .env
carylle-admin gen-cert --host carylle.example.internal --out deploy/tls
docker compose up -d --build
```

**Agents:** issue a token for each host (run this where `CARYLLE_AGENT_MASTER_SECRET` is set):

```sh
carylle-admin agent-token web-01
```

Then install using the steps at the top of
[deploy/systemd/carylle-agent.service](deploy/systemd/carylle-agent.service). Point `verify_tls` at
`cert.pem` if you're using the bootstrap certificate.

Roll out in stages, as described in [SECURITY.md](SECURITY.md#safe-rollout).

## Operating it

All operator calls need `Authorization: Bearer $CARYLLE_OPERATOR_TOKEN`.

| Call | Purpose |
|---|---|
| `GET /api/v1/status` | Mode, LLM state, pending approvals |
| `GET /api/v1/cases` | Recent cases |
| `GET /api/v1/cases/{id}` | One case, with events, ATT&CK details and actions |
| `GET /api/v1/actions?state=pending_approval` | Actions waiting for a decision |
| `POST /api/v1/actions/{id}/approve` | Body: `{"operator": "name"}` |
| `POST /api/v1/actions/{id}/reject` | Body: `{"operator": "name", "note": "why"}` |
| `POST /api/v1/response/mode` | Body: `{"mode": "observe", "operator": "name"}` |
| `GET /api/v1/agents` | Agents, last seen and sensor health |
| `GET /api/v1/ledger` | Audit trail |
| `GET /api/v1/ledger/verify` | Check the ledger hasn't been tampered with |

Interactive API docs are at `/docs` on the server.

To undo a quarantine, on the affected host:

```sh
carylle-agent quarantine-list
carylle-agent quarantine-restore <id>
```

## Configuration

| File | Controls |
|---|---|
| [config/settings.yaml](config/settings.yaml) | Thresholds, limits, LLM model and effort, sensors |
| [config/safelist.yaml](config/safelist.yaml) | What must never be touched. **Review this for your environment** |
| [config/playbooks/response_playbooks.yaml](config/playbooks/response_playbooks.yaml) | Which actions each kind of threat permits |
| [config/yara/](config/yara/) | YARA rules. Add your own `.yar` files here |
| `.env` | Secrets. See [.env.example](.env.example) |

Detection rules are in
[fallback_scorer.py](server/carylle/pipeline/reasoning/fallback_scorer.py). Each has a weight, and
scores combine so that independent evidence adds up.

## LLM cost and behaviour

Only flagged activity reaches the model, repeats within the cooldown skip it, and
`max_calls_per_minute` caps spend. Any failure, including a timeout, outage, exhausted budget or
declined request, falls back to the deterministic verdict, so detection doesn't depend on the API.

Security telemetry can trip the API's safety classifiers, so requests set `fallbacks: "default"`,
which retries a declined request on Anthropic's recommended fallback model. Turn it off with
`llm.server_side_fallbacks: false`.

## Testing

```sh
pytest
```

The suite covers each pipeline stage, the real Anthropic SDK against a mock transport, a deliberately
compromised model, real process termination and file quarantine on child processes and temp files,
and end-to-end runs against a live server. Tests never touch anything they didn't create.

Purple team reports (`purple-report.md`, `.json`) score each scenario and list ATT&CK coverage.

ATT&CK renumbers techniques between releases, and tests fail if any rule or playbook cites an ID
missing from the bundled dataset. Run `make mitre-update` to update the dataset and re-check.

## Known limitations

- The process sensor polls, so it can miss processes that live under a second. eBPF or ETW sensors
  would be the next step, and the event format wouldn't change.
- No host isolation action yet: containment means terminating processes and quarantining files.
- API only, with one shared operator token. There's no UI or per-user accounts, and alerts aren't
  pushed anywhere, so you need to poll `/api/v1/cases`. Nothing alerts on an agent going silent.
- SQLite suits a small fleet. A larger one would need a real database and a queue.
- Primarily built and lab-tested for Linux endpoints. The agent's code is cross-platform and its tests
  pass on Windows, but there's no Windows service definition yet, and the Windows rules are less
  thoroughly covered.

## Layout

```
agent/carylle_agent/   Endpoint agent: sensors, scanners, actuators, transport
server/carylle/        Server: API, pipeline, reasoning, response
config/                Settings, safelist, playbooks, YARA rules
purple/                Purple team harness
data/mitre/            MITRE ATT&CK dataset
deploy/                Dockerfiles, systemd unit
tests/                 Test suite
```
