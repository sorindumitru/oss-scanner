# SPIRE threat model for OSS Scanner

SPIRE is the reference implementation of the SPIFFE specifications. It attests
nodes and workloads and issues them short-lived identities (X.509-SVIDs,
JWT-SVIDs and, experimentally, WIT-SVIDs). A SPIRE Server is the signing
authority of a trust domain; a SPIRE Agent runs on every node and serves
identities to local workloads.

The security property that matters most: **an identity is only ever issued to
a node or workload that is entitled to it by attestation and registration
entries, and a trust bundle only ever contains keys its trust domain
published.** Anything that breaks this is what we most want to hear about.

## Components and trust boundaries

| Component | Code | Exposed to |
|-----------|------|------------|
| Server TCP API (gRPC, TLS/mTLS) | `pkg/server/api`, `pkg/server/endpoints` | Network; callers are unauthenticated, agents, admin or downstream workloads |
| Server local API (UDS / named pipe) | same, plus `cmd/spire-server` | Local users who can open the socket; treated as full admin |
| Federation bundle endpoint (`https_web`, `https_spiffe`) | `pkg/server/endpoints/bundle` | Network, unauthenticated |
| Federation bundle client | `pkg/server/bundle/client` | Responses from federated trust domains |
| Node attestors (server and agent sides) | `pkg/server/plugin/nodeattestor`, `pkg/agent/plugin/nodeattestor`, `pkg/common/plugin` | Attestation payloads from unauthenticated network callers |
| Agent Workload API and Envoy SDS API (UDS / named pipe) | `pkg/agent/endpoints` | Every local process that can reach the socket |
| Workload attestors and peer tracking | `pkg/agent/plugin/workloadattestor`, `pkg/common/peertracker`, `pkg/common/containerinfo` | Local processes trying to look like another workload |
| Agent admin API (Delegated Identity, debug) | `pkg/agent/api` | Local processes; delegates listed in `authorized_delegates` |
| Agent Broker API | `pkg/agent/broker` | mTLS callers; authorized brokers act for workloads they reference |
| SVID and token validation | `pkg/common/jwtsvid`, `pkg/common/x509svid`, `pkg/common/x509util`, `pkg/common/witutil` | Attacker-supplied certificates and tokens |
| CA, key managers, upstream authorities | `pkg/server/ca`, `pkg/server/plugin/keymanager`, `pkg/server/plugin/upstreamauthority` | Internal; hold the signing keys |
| Authorization policy and entry authorization | `pkg/server/authpolicy`, `pkg/server/authorizedentries`, `pkg/server/endpoints` | Decides which caller reaches which RPC and which agent gets which entry |
| Datastore | `pkg/server/datastore` | Internal; input arrives through the APIs above |
| OIDC Discovery Provider | `support/oidc-discovery-provider` | Internet, unauthenticated |

Default RPC authorization lives in `pkg/server/authpolicy/policy_data.json`.
Only `AttestAgent` and `GetBundle` are reachable without authentication.

## Attackers to assume

In rough order of interest:

1. **Unauthenticated network attacker** who can reach the server TCP port, the
   bundle endpoint or the OIDC Discovery Provider.
2. **Unprivileged local process** on a node running an agent. It can reach the
   Workload API socket. It must not obtain an SVID for an entry whose selectors
   it does not match, must not confuse the agent about which process is
   calling (PID reuse, exec races, container or cgroup spoofing), and must not
   reach the admin API unless it is an authorized delegate.
3. **Attested but malicious agent** (a compromised node). It legitimately holds
   its own agent SVID and can obtain SVIDs for entries parented to it. It must
   not obtain identities for entries outside its authorization, impersonate
   another agent, survive a ban or eviction, or escalate to admin or downstream
   rights.
4. **Malicious workload with a valid SVID**, including one from a federated
   trust domain. It must not gain agent, admin or downstream rights it was not
   registered with.
5. **Malicious federated trust domain** that controls its own bundle endpoint.
   It may put anything in its own bundle. It must not alter the local trust
   domain's bundle or another federated domain's bundle, obtain local
   identities, or crash or exhaust the server through endpoint responses.
6. **Malicious delegated-identity or broker client** that is authorized for
   some workloads. It must not obtain identities beyond what its configuration
   allows.
7. **Network man-in-the-middle** between agent and server, or between server
   and a federated bundle endpoint.

## Trusted, and therefore out of scope

Findings that need one of these as a precondition are not vulnerabilities:

- Root or administrator on the server host, or anyone who can read the server
  data directory, key manager backend, or configuration.
- Anyone who can open the server's local API socket. That socket is the admin
  interface by design.
- Anyone with write access to the datastore (SQL database).
- Workloads registered with `admin` or `downstream`. Admin controls the trust
  domain. Downstream receives an intermediate CA and can sign any identity in
  the trust domain; this is how nested SPIRE works.
- Root on an agent node. Root can read the agent's keys and impersonate every
  workload registered on that node.
- Plugin binaries and their configuration. External plugins are run as
  subprocesses with the privileges of the server or agent.
- The platforms attestors rely on: cloud provider APIs and instance metadata,
  the Kubernetes API server and kubelet, the container runtime, the TPM and
  its manufacturer CA, the upstream CA.
- The operator. Insecure configuration that is documented as such is not a
  finding, for example `insecure_bootstrap`, `skip_kubelet_verification`,
  the `disk` and `memory` key managers, exposing the profiling or health
  endpoints on a public interface, or world-accessible socket directories.

Known and accepted properties, please do not report:

- Join tokens are single-use bearer secrets; whoever presents one first wins.
- Several node attestors are trust-on-first-use.
- A compromised agent can request SVIDs for every entry parented to it.
- The `unix` workload attestor cannot tell apart processes with the same
  uid/gid unless other selectors are used.
- X.509-SVIDs and JWT-SVIDs are not revocable before expiry; short lifetimes
  are the mitigation.
- JWT-SVIDs are bearer tokens and can be replayed by whoever holds one.
- Anyone who can reach the Workload API socket can fetch the trust bundle.
- Admins can create entries that overload the server.

Code out of scope:

- `test/`, `examples/`, `script/`, `.github/`, `release/`, `doc/`, and all
  `*_test.go` files. Keys and certificates in these paths are fixtures.
- Generated code under `proto/`.
- Third-party dependencies, including `spiffe/go-spiffe`, `spiffe/spire-api-sdk`
  and `spiffe/spire-plugin-sdk`, unless SPIRE's use of them is what makes the
  bug exploitable. A dependency with a known CVE is not a finding without a
  reachable path in SPIRE.

Features behind `experimental` configuration or a feature flag
(`pkg/common/fflag`) are in scope. Say so in the report; severity is capped at
high.

## Severity

Rate by what the weakest attacker who can exploit it gains, in a default or
documented-as-recommended configuration.

**Critical**
- An unauthenticated network attacker, or an unprivileged local process,
  obtains an agent SVID, an SVID for an arbitrary SPIFFE ID, a CA or JWT
  signing key, or a signature over attacker-chosen content.
- Node attestation bypass in a built-in attestor that lets an attacker join
  as an agent without the credential the attestor is meant to verify.
- Injection of attacker keys into the local trust domain's bundle.
- Remote code execution in the server or agent.
- Authentication bypass giving admin or downstream rights on the server API.

**High**
- A local process obtains the SVID of another workload on the same node
  (workload attestation bypass, peer tracking race).
- An attested agent obtains SVIDs for entries not authorized to it, or keeps
  access after being banned or evicted.
- A federated trust domain alters a bundle other than its own.
- SVID or token validation accepts something it must reject (wrong trust
  domain, wrong audience, expired, bad signature, algorithm confusion).
- SQL injection or datastore corruption reachable from a non-admin caller.
- Unauthenticated remote crash or unbounded resource use of the server.
- Disclosure of private key material to a non-root party.

**Medium**
- Crash or resource exhaustion of the server by an attested agent or a
  federated bundle endpoint.
- Crash or resource exhaustion of the agent by an unprivileged local process.
- Authorization gaps that leak registration entries, selectors or agent
  inventory to a caller that should not see them.
- Rate-limit bypass on unauthenticated RPCs.
- Critical or high impact that needs a non-default but reasonable
  configuration.

**Low**
- Hardening gaps with no demonstrated impact, issues that need an unlikely
  configuration, minor information leaks, log injection, time-of-check races
  with no practical window.

Not security findings: bugs that only an admin can trigger, panics in CLI
argument parsing, missing best practices with no attack path, and anything
that needs a trusted party listed above.

## Reports

Each report should have:

- A one-line title naming the component and the impact.
- Affected file and function, and the commit scanned.
- Which attacker from the list above is needed, and any configuration that
  must be set. State whether the configuration is the default.
- The path from attacker-controlled input to the faulty code, with file and
  line references.
- A proof of concept.
- Suggested severity with a one-sentence justification against the rubric.

Proofs of concept we find useful, best first:

1. A Go test that fails on the current code, placed next to the affected
   package and using the helpers in `test/` (`spiretest`, `fakes`, `testca`).
2. A script against a server and agent built from this repository, in the
   style of `test/integration/suites`.
3. A crafted input (attestation payload, certificate, token, bundle document)
   with the command that feeds it to the code.

A panic or memory blow-up needs the input and the stack trace or a memory
measurement. "This looks unbounded" is not enough.

Patches: keep them minimal and limited to the fix plus a regression test. Do
not refactor, rename, or bump dependencies. Follow `CONTRIBUTING.md`; the fix
must pass `make lint` and `make test`. Mention any behaviour change an operator
could notice, and whether the fix needs backporting to the previous minor
release (see `SECURITY.md`).

Reports are confidential. Vulnerabilities go to security@spiffe.io, not to
public issues or pull requests.

## Deduplication

- One report per root cause. The same missing check reached through several
  RPCs, or through both the POSIX and Windows code paths, is one report that
  lists every entry point.
- The same class of bug in separate plugins with separate code (for example
  two node attestors) is one report per plugin.
- A bug in shared code (`pkg/common/...`) is one report, listing the affected
  callers.
- If one fix would close several findings, they are one report.
- Variants found after a fix has landed are new reports that reference the
  original.
