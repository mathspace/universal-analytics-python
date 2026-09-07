# universal-analytics-python threat model

## Overview

A Python 2 library builds Universal Analytics Measurement Protocol hits and sends them to Google Analytics over urllib2, using POST by default or query-string GET when selected. It accepts caller account/client/user identifiers, persistent parameters and per-hit data. It is an outbound telemetry client with no inbound authentication service (UniversalAnalytics/Tracker.py:73; UniversalAnalytics/Tracker.py:215; UniversalAnalytics/Tracker.py:243).

Client identity and telemetry account selection are supplied by the application; neither is a credential issuance or user-authentication protocol here. Parameter conversion helps form protocol payloads, but cannot establish whether sending a value is appropriate. The repository is historical Python 2 client code. This offline model does not assert current Analytics service acceptance, present-day SDK support, deployed runtime TLS behavior or an organization-specific recipient.

| Component | Source |
| --- | --- |
| Hit construction and tracker state | UniversalAnalytics/Tracker.py:158; UniversalAnalytics/Tracker.py:215; UniversalAnalytics/Tracker.py:243 |
| POST/GET transport and error handling | UniversalAnalytics/Tracker.py:98; UniversalAnalytics/Tracker.py:108; UniversalAnalytics/Tracker.py:125 |
| Optional HTTP output translator | UniversalAnalytics/HTTPLog.py:99; UniversalAnalytics/HTTPLog.py:112 |
| Local package release workflow | Makefile:31; setup.py:4 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Default tracker | POST telemetry | Tracker use_post=True default → HTTPPost → inherited endpoint → urllib2 Request body | https://www.google-analytics.com/collect, URL-encoded request body by default | Google Analytics and runtime-configured intermediaries | HTTPS urllib2 transport plus caller payload/account selection | UniversalAnalytics/Tracker.py:73; UniversalAnalytics/Tracker.py:125; UniversalAnalytics/Tracker.py:215 |
| GET tracker | GET telemetry | Tracker use_post=False → HTTPRequest → inherited endpoint + encoded query | https://www.google-analytics.com/collect?&lt;URL-encoded payload&gt; when use_post=False | Analytics plus any URL/debug log recipients | Caller selection; runtime HTTPS | UniversalAnalytics/Tracker.py:98; UniversalAnalytics/Tracker.py:217 |
| Optional debugging | HTTP debug output | Explicit HTTP debug opener and HTTPLog.consume(outbuffer or sys.stdout) | Process stdout or supplied output buffer via HTTPLog.consume | Console/log collector | Explicit debug configuration and host log access | UniversalAnalytics/HTTPLog.py:99; UniversalAnalytics/HTTPLog.py:112 |
| Manual maintainer Makefile upload | Package upload | Local clean-tree/test/version/build prerequisites → setup.py sdist bdist upload → Python packaging repository configuration | Built UniversalAnalytics distributions to externally configured package index; exact index/credential reference not declared by repository | Configured package registry and downstream installers | Maintainer command authority, local prerequisites, external package-index authentication | Makefile:31; setup.py:4 |

## Threat Model, Trust Boundaries, and Assumptions

**Protected assets.** Tracking account identifier, client/user IDs, page/event/transaction attributes and other caller-provided telemetry sent to the configured analytics recipient (UniversalAnalytics/Tracker.py:215; UniversalAnalytics/Tracker.py:243). Host request availability and release package integrity; diagnostic HTTP output can include transmitted data (UniversalAnalytics/Tracker.py:77; UniversalAnalytics/HTTPLog.py:99).

**Actors and starting authority.** Host end users may influence event attributes via the integration but have no intrinsic ability to select Python classes, opener settings or endpoint overrides. A caller who can configure the tracker controls telemetry attribution and destination code; this is application authority, not a new privilege from user input.

**Trust boundaries and owned controls.**

- Caller data passes through supported hit-type checks, parameter aliases/type conversions and URL encoding; leading & parameter names permit raw parameter passthrough. Protocol acceptance is not consent, anonymization or authorization to disclose data (UniversalAnalytics/Tracker.py:158; UniversalAnalytics/Tracker.py:243).
- POST and GET share HTTPS endpoint but expose payload differently: POST body versus URL query. TLS implementation, certificate validation and proxy behavior are inherited from the actual Python runtime/opener, not implemented as custom controls here (UniversalAnalytics/Tracker.py:98; UniversalAnalytics/Tracker.py:125).
- Optional client hashing uses deterministic MD5-derived identifier for string input, distinct from random UUID generation and not a secrecy guarantee (UniversalAnalytics/Tracker.py:24).
- HTTP debug enables a process-global opener; HTTPLog can replace stdout with a translator that renders request/response contents. Log readers are additional recipients (UniversalAnalytics/Tracker.py:77; UniversalAnalytics/HTTPLog.py:112).
- Maintainer Makefile release/upload invokes setup.py distribution upload after local checks; package version derives from commit-version. Developer package registry credentials and publication policy are external (Makefile:31; setup.py:4).

**Security objectives.** Send only intended data to the intended analytics account and restrict optional HTTP logs. Treat hashed identifiers as linkable values; enforce privacy/minimization in the caller. Choose runtime transport and timeout/failure handling appropriate to host availability needs.

**Assumptions and unresolved controls.**

- No current service availability is asserted: offline source describes the historical Measurement Protocol API.
- urlopen is called without an explicit timeout. URLError invokes a cache_request stub, and HTTPError returns false; no durable retry queue is implemented (UniversalAnalytics/Tracker.py:108).
- Actual runtime TLS verification, proxy configuration, event contents, account audience and log permissions remain unresolved. No cookie/session middleware, inbound endpoint or access-enforcement layer is implemented by the reviewed client.

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses, not validated vulnerabilities. Each requires its stated caller, data and exposure prerequisites; ordinary use of authority already granted is not a new capability.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | User-identifying or secret-bearing event data is sent to an analytics account or debug reader outside its intended audience. | A host includes sensitive parameters or enables HTTP diagnostics accessible to less-privileged readers. | External or secondary-log disclosure of telemetry contents. | Caller payload selection, URL encoding, HTTPS endpoint and optional debug enablement. | Minimize data before send and separately govern account, GET URLs and debug output. | UniversalAnalytics/Tracker.py:98; UniversalAnalytics/Tracker.py:215; UniversalAnalytics/HTTPLog.py:99 |
| 2 | Deterministically hashed client identifiers are treated as anonymous and disclosed or reused without considering linkability. | A host hashes guessable source identifiers and relies on hashing as a privacy boundary. | Identification/linkage from persistent telemetry. | Random UUID option; hashing is explicitly MD5-derived for string input. | Choose identifiers and retention suited to the caller privacy contract; do not treat hashing as encryption. | UniversalAnalytics/Tracker.py:24 |
| 2 | Synchronous transport stalls or loses hits while a host assumes bounded latency or durable delivery. | The tracker runs in a latency-sensitive path and the configured runtime/network fails. | Host availability impact or incomplete analytics; security impact requires real downstream reliance. | HTTPError/URLError handling; cache_request exists only as a stub. | Set an appropriate host transport budget and design independently for any required durable delivery. | UniversalAnalytics/Tracker.py:108; UniversalAnalytics/Tracker.py:117 |
| 3 | A lower-trust artifact or configuration change alters installed tracker code or the intended recipient. | A demonstrated publisher/installer/configuration boundary failure; a trusted caller choosing its own destination is not an exploit. | Execution under the host Python account or redirected telemetry. | Local clean-tree/test steps in upload workflow; endpoint defaults to HTTPS. | Protect approved source/releases and validate intended runtime destination configuration. | Makefile:31; UniversalAnalytics/Tracker.py:73; setup.py:4 |

## Severity Calibration (Critical, High, Medium, Low)

| Level | Repository-specific example | Counterexample or limiting prerequisite |
| --- | --- | --- |
| Critical | A proven package-supply failure compromises broad privileged downstream installations. | Requires an actual lower-trust publication path and consequential privileges; no such failure is validated here. |
| High | A real integration exports substantial sensitive data or reusable privileged secrets to unauthorized recipients. | The data, recipient and lack of entitlement must be shown; ordinary analytics events do not imply high impact. |
| Medium | Transport behavior materially disrupts a shared host service or exposes limited confidential metadata. | A background best-effort analytics loss without security dependence is generally lower impact. |
| Low | An isolated hit is rejected or lost, or optional debugging produces non-sensitive diagnostics. | Intentional telemetry transmission to an authorized account is the library’s function, not a vulnerability. |

This model uses an independent source-backed architecture pass. Repository citations were checked against the supplied inventory and source lines; application code and external services were not executed. Source-established behavior is distinct from unverified deployment exposure. Revisit the model when the described input, storage, authorization or publication boundaries change.

Repository: github.com/mathspace/universal-analytics-python
Version: 78ee36a5f1efc144043ae003c855b97fbe662f7c
