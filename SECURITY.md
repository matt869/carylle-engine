# Security

Carylle can kill processes and move files on the machines it protects, and its reasoning
layer reads text written by attackers. This page describes what it defends against, what it
doesn't, and how to run it safely.

## Reporting a vulnerability

Report vulnerabilities privately to the project maintainers, not in a public issue. Include
reproduction steps and the affected version.

> **Before publishing this project:** add a real security contact here.

## Threat model

### The model is assumed to be manipulable

Command lines, file names and DNS queries are attacker-controlled, and all of them reach the
model. Prompt injection can't be fully prevented by filtering, so Carylle limits what a
successful injection can achieve.

| If an attacker hijacks the model and makes it... | What happens | Enforced in |
|---|---|---|
| Kill an arbitrary PID, or quarantine an arbitrary file | Not expressible. The model can only cite an event reference, and the target is read from that stored event | `verdict_validator.py`, `orchestrator.py` |
| Target an innocent process it saw in the same case | Held for an operator. Unattended action needs deterministic rules to have flagged that exact event | `guardrails.py` |
| Call a reverse shell benign | The deterministic floor keeps the severity and the containment action | `verdict_validator.py` |
| Target something critical | Denied by the safelist, which no operator or model can override | `guardrails.py`, agent `safelist.py` |
| Return malformed or incoherent output | Discarded, and the deterministic verdict is used | `verdict_validator.py` |

**One deliberate trade-off.** If the model disagrees with strong rules and no injection text is
detected, the action waits for a person, because that's a plausible false positive. An attacker
who gets an injection past the detector could therefore delay containment. They can't suppress
the alert: the case still appears as high severity with an action awaiting approval. The opposite
choice would let any false positive kill production processes over the model's objection.

Injection text that *is* detected doesn't cause this delay. Otherwise, appending "ignore previous
instructions" to a command line would be an easy way to turn off autonomous response.

### Other protections

- **Commands are signed with Ed25519.** Agents hold only the public key, so a compromised
  endpoint can't forge commands for other hosts.
- **Commands are single-use and short-lived.** Agents check the signature, addressee, expiry and
  a replay cache that survives restarts.
- **The agent doesn't trust the server.** Before acting it re-checks the live process start time
  (PID reuse), the live executable path, the file hash and its own copy of the safelist.
- **Agent tokens are per host,** and a host's identity comes from its token, not its payload.
- **The ledger is tamper-evident.** An HMAC hash chain plus an external anchor detects edits,
  deletions and truncation.
- **Secrets are redacted** from everything sent to the model.

### What Carylle does not protect against

- **A compromised server.** It holds the signing key. The agent's own checks limit the damage
  but can't stop a signed command against a target that isn't safelisted. Protect the server,
  and consider running hosts in `approve` mode.
- **Root on an endpoint.** An attacker with root can stop the agent or feed it false telemetry.
  A silent agent shows up as a stale `last_seen` in `/api/v1/agents`, but nothing alerts on it yet.
- **Very short-lived processes.** The process sensor polls once a second, so a process that lives
  for less than that can be missed. Use eBPF or ETW sensors for full coverage.
- **Fileless and in-memory attacks,** beyond what command lines reveal. There's no memory scanning.
- **An attacker reading the ledger key.** With the key, a chain can be rewritten. Store the anchor
  file somewhere the server can't overwrite if this matters to you.

## Data leaving your network

With the LLM enabled, sanitized telemetry from flagged cases is sent to the Anthropic API:
process names, command lines, paths, hashes, usernames, hostnames and IP addresses. Activity that
no rule flags is never sent. Known secret formats are redacted first, but pattern-based redaction
can miss things, so review this against your data handling requirements. Set
`CARYLLE_LLM_ENABLED=false` to keep everything local. Detection and response keep working.

Unredacted telemetry stays in the server's database. Protect it accordingly.

## Safe rollout

1. Deploy agents with `actuators_enabled: false`, the default, and the server in `observe` mode.
2. Review what *would* have happened, and tune the safelist and rules for your environment.
3. Enable actuators on a few hosts with the server in `approve` mode.
4. Only then consider `autonomous`, ideally for specific low-risk host groups.

To stop all response actions immediately:

```sh
curl -X POST https://your-server:8443/api/v1/response/mode \
  -H "Authorization: Bearer $CARYLLE_OPERATOR_TOKEN" -H "Content-Type: application/json" \
  -d '{"mode": "observe", "operator": "your-name"}'
```

## Hardening checklist

- Use TLS with a real certificate, or pin the bootstrap one through `verify_tls: /path/to/cert.pem`.
- Keep `.env` out of version control and restrict its permissions. Rotate `CARYLLE_OPERATOR_TOKEN`
  if it's ever exposed.
- Don't expose the operator API to the internet. It has one shared token and no per-user accounts,
  so the `operator` name in approvals is self-reported.
- Keep agent clocks in sync with NTP, since command expiry relies on them.
- Revoke a lost agent by adding its ID to `server.revoked_agents`.
- Run `carylle-admin verify-ledger` on a schedule.

## Purple team safety

`purple/runner.py` contains no real attack tooling. Synthetic mode only posts data. Live mode
runs harmless decoys and refuses to start unless `CARYLLE_LAB=1` is set **and** `/etc/carylle-lab`
exists, which is only true in the lab image. The lab network has no route out.

The test suite never writes EICAR or web shell samples to disk, because real antivirus reacts to
them. Live purple mode does write the EICAR string, but only inside the lab container.
