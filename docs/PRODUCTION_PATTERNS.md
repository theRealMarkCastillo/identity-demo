# Production Patterns: Deploying This Reference & Building Products for AI Agents

## 0. How to Read This Doc

This is the **"what do I do with this?"** companion to [ARCHITECTURE.md](ARCHITECTURE.md). Read ARCHITECTURE first if you haven't — every pattern here assumes you already understand the demo's mechanics (three principals, RS256 + JWKS, RFC 8693 token exchange, `SET LOCAL` → RLS).

**Two audiences, one doc:**

1. **§2 — Deployment archetypes.** You're shipping a system with users and agents and you need to know which production shape fits your constraints (multi-tenant SaaS, regulated industry, zero-trust, air-gapped, etc.). For each archetype: what transfers directly, what changes, what's added.
2. **§3 — Products and services for AI agents.** You're building something *new* in the agent economy — an MCP server, an agent marketplace, an observability product, a permission broker — and you want to know how this demo's identity model fits. For each product category: what's the value-prop, what parts of the demo are your core, what's missing.

**§1 — Universal transfer checklist.** Before picking an archetype, scan this. Ten properties this demo gives you out of the box; ten properties every production system needs whether you use this pattern or not. The diff between those two sets is what you're actually adopting.

**§4 — Decision matrix.** A short "if you are X, start with Y" reference. Read this first if you're in a hurry.

**§5 — Open questions.** The agent-identity space is moving fast. Things this demo deliberately doesn't decide yet, and how to think about them.

Terminology used here is defined in [ARCHITECTURE.md §12](ARCHITECTURE.md#12-glossary). The Glossary is the source of truth for `principal`, `actor`, `downscoping`, `GUC`, etc.

---

## 1. The Universal Transfer Checklist

These ten properties are present in the demo **as built**. They show up in any system that adopts this pattern. They're not deployment-specific — they're the *base load* you're picking up.

| # | Property | What it means | Where it lives in the demo |
|---|---|---|---|
| 1 | **Three-principal model** | Your system distinguishes human-direct, delegated-agent, and headless-agent actions in the JWT and the audit log. | `db/init.sql` + RFC 8693 grants |
| 2 | **Cryptographic identity** | No layer "trusts" upstream identity — every verifier checks RS256 + `iss` + `aud` + `exp` + `jti`. | `web-app/app/jwt_verify.py` + DB-side optional verify |
| 3 | **Principal/actor preserved end-to-end** | Every audit row has both `sub` and `act_sub`. You can always answer "who triggered this, and what ran the code?" | `platform.audit_log` schema + every grant handler |
| 4 | **Scope downscoping at delegation** | RFC 8693 mints `effective = subject.scopes ∩ actor.scopes`. A copilot cannot escalate above its delegation. | `control-plane/app/routes/token.py:_grant_token_exchange` |
| 5 | **Database as last line of defense** | RLS rejects unauthorized writes even if the application is wrong, compromised, or absent. | `db/init.sql` policies + `app_session` role |
| 6 | **Identity-in-session, not in-queries** | `SET LOCAL` carries identity, not SQL text. Immune to SQL injection, query-log leakage, and pool cross-talk. | `web-app/app/db.py:run_with_identity()` + `cli-agent/tools.py` |
| 7 | **Revocation that works** | `jti` lookup + RFC 7009 endpoint. Kill any token mid-flight, including a delegated-agent's. | `platform.token_records` + `/oauth/revoke` |
| 8 | **Non-superuser DB role** | Connection pools can't bypass RLS; blast radius of app compromise is bounded. | `app_session` grant in `init.sql` |
| 9 | **Split-the-world token strategy** | Browser sessions are stateful; API tokens are stateless JWT; resource-server verifications don't need a callback. | `web-app/app/session.py` vs `jwt_verify.py` |
| 10 | **Per-event audit trail** | Every token lifecycle event and every RLS block is recorded. Distinguishes "user did X" from "user's agent did X." | `platform.audit_log` + `platform.token_records` |
| 11 | **Column-level masking with a principal-type floor** | PII cells return masked values to agents *unconditionally*, with raw clearance only for entitled humans. The mask decision lives in the DB, not the app. | `db/init.sql:apply_mask()` + `target.transactions_masked` + `roles.compute_umask` |

These are the properties you're adopting. They're not free — operating an AS, an audit log, and an RLS-aware schema all cost work — but they're the value-prop of the pattern.

These ten properties are **not** in the demo. They're production hardening regardless of architecture:

| # | Property | What production adds |
|---|---|---|
| 1 | **HTTPS / mTLS everywhere** | TLS termination at the edge; mTLS between services; cert pinning on mobile. |
| 2 | **Secret management** | HSM / KMS / Vault — never `.env` on disk. |
| 3 | **MFA and step-up auth** | WebAuthn / TOTP / risk-based. Step-up for destructive ops. |
| 4 | **Policy versioning + change audit** | GitOps for `platform.role_scopes`; CI diffs; rollback. |
| 5 | **Append-only audit log** | IMMUTABLE / hash-chain / external SIEM. Demo's log is mutable by `control_plane_admin`. |
| 6 | **Rate limiting + DoS defense** | Edge WAF, per-client quotas, LLM-cost ceilings. |
| 7 | **Observability** | Metrics, traces, anomaly detection. Demo has logs, not SLOs. |
| 8 | **High availability** | Multi-AZ, read replicas, AS cluster, DB failover. |
| 9 | **Data residency / sovereignty** | Per-region key custody, in-region AS, residency-bound tokens. |
| 10 | **DPoP / sender-constrained tokens** | RFC 9449 — bind the token to the TLS key so a stolen token can't be replayed. |

The diff between the two tables — the asymmetry between *what you get free with the pattern* and *what you always have to add on top* — is the practical reason to adopt. You're not avoiding work; you're choosing which work you do.

---

## 2. Production Deployment Archetypes

Each archetype below has the same shape:

- **The shape.** Who you serve, what's regulated, where it runs.
- **What transfers directly.** Which of the 10 universal properties fit without modification.
- **What changes.** Specific swaps from this demo to your context.
- **What's added.** The hardening from the "not in the demo" column, with emphasis on what this archetype *uniquely* needs.
- **Concrete cut.** The shortest path from this demo to a working instance of this archetype.

### 2.1 Multi-Tenant SaaS

**The shape.** You're a B2B SaaS company. Each customer ("tenant") brings their own users. Some tenants will bring their own IdP (Okta, Entra ID, Google Workspace). All tenants share your database, your AS, and your application. Your customers want per-tenant isolation, per-tenant audit, and per-tenant billing.

**What transfers directly.** #1, #2, #3, #4, #5, #6, #7, #8, #9, #10 — all of them. The demo is already multi-tenant-safe at the *principal* level (you can issue tokens for any user_id). What's missing is tenant as a first-class concept.

**What changes.**

- Add `tid` (tenant id) as a claim in every JWT. Issue it from `platform.tenants`. The RLS policies become `(owner_user_id = current_user_id() OR current_tid() IS NULL) AND tenant_id = current_tid()`. Every query now requires a tenant. Pool cross-talk between tenants becomes impossible by construction.
- Your IdP story splits: tenants with their own IdP use **OIDC federation** (your AS trusts their IdP's signed `id_token`, issues your own access token with `tid` set). Tenants without one use your hosted login (lift the demo's control-plane login UI into a tenant-themed page).
- Per-tenant encryption keys (envelope encryption via KMS) for sensitive columns. RLS doesn't solve encryption-at-rest; you'd add it as an additional layer.

**What's added.**

- **Tenant onboarding flow.** UI + DB transaction that creates the `platform.tenants` row, the tenant's first admin user, the tenant's default role bindings, and (if applicable) the federation trust with their IdP.
- **Per-tenant rate limits and quotas.** Especially LLM cost ceilings — one tenant can drain your budget.
- **Cross-tenant audit visibility.** A `super_admin` role that can read across tenants *without* a tenant-id GUC — typically a separate connection role (`super_admin_session`) created via a break-glass procedure with its own audit trail.
- **Tenant-scoped client secrets.** The demo's `platform.clients` table is global. In multi-tenant, each tenant has its own client registry; the `client_id` is namespaced (`tenant_42:web-app`).

**Concrete cut.** Start with the demo as-is, then: (1) add `tid` claim + `current_tid()` GUC + RLS branch on every policy; (2) bring your existing `platform.users` table into `platform.tenant_users` with `(tenant_id, user_id)` as composite key; (3) wrap `POST /oauth/tenants/onboard` around tenant creation. Total scope: ~1 week for a small schema change, plus the harder work of tenant isolation testing (which is where most multi-tenant security bugs are found).

---

### 2.2 Regulated Industry (Healthcare / Financial / Government)

**The shape.** You're in HIPAA, PCI-DSS, FedRAMP, SOC 2 Type II, or equivalent. Audit trails aren't a feature — they're an audit finding if you get them wrong. Tokens must be short. Destructive ops need step-up auth. The audit log must be tamper-evident.

**What transfers directly.** All 10. With restrictions: #5 (RLS as last line of defense) becomes *more* important, not less, when the auditor asks "show me a query that succeeded."

**What changes.**

- Tokens shrink. 1h access → 5–15 min. 8h refresh → 1h with re-auth. Step-up auth required to issue tokens with destructive scopes (`delete:*`, `admin:*`).
- Audit log becomes append-only at the database level. Postgres `REVOKE UPDATE, DELETE ON platform.audit_log FROM control_plane_admin`; the audit writer role has `INSERT` only. Optionally add a hash-chain trigger (`audit_log.prev_hash = SHA256(last_row || details)`) so any retroactive mutation breaks the chain cryptographically.
- Specific RLS branches for "minimum necessary" (HIPAA). A nurse-role token can read only the patients on the nurse's unit; a billing-role token can read only encounters with billing flags. This is enforced via row-level tags, not application logic.
- **Break-the-glass access.** Auditors expect a named procedure where, in an emergency, an admin can read across the usual RLS. The procedure: a separate connection role, MFA step-up, a dedicated `audit_log.event_type='break_glass'` row, and a notify-the-CISO hook.

**What's added.**

- **HSM-backed signing keys.** `control-plane/keys/signing.pem` on disk is a finding. Move the private key to AWS KMS / GCP CloudHSM / Azure Key Vault with *envelope encryption* — the AS decrypts the signing key in memory at startup, never persists it.
- **Per-tenant data residency.** Especially for EU customers (GDPR), US gov (FedRAMP), or APAC. Your AS cluster runs in-region; tokens are bound to a region via `region` claim; RLS rejects rows whose residency tag doesn't match.
- **Customer-managed keys (BYOK).** Some tenants (banks, governments) demand that *they* hold the encryption keys for their data, not you. Envelope encryption via their KMS makes this possible without rebuilding the app.
- **Audit log export.** Auditors will ask for raw rows. The audit log table should be exportable to a long-term store (S3 with object lock, QLDB, immudb) that *you* can't mutate from the app's role.
- **Penetration testing + SOC 2 audit cadence.** Annual third-party pen test; continuous SOC 2 controls; HIPAA risk assessment. Out of scope for this section but mentioned because regulated buyers will gate on them.

**Concrete cut.** Take the demo's audit table and (1) drop UPDATE/DELETE permissions, (2) add a hash-chain trigger, (3) sink writes to an external append-only store. Move the signing key to your KMS. Shrink token TTLs. Add step-up auth on the destructive-scope issuance path. Total scope: 2–3 weeks for the security-critical changes (the rest is documentation and process).

---

### 2.3 Zero-Trust / High-Security (DPoP, mTLS, No Implicit Trust)

**The shape.** You're shipping to a security-paranoid customer — federal, defense, finance with strict infosec, or a security-mature enterprise where every layer authenticates. Trust assumptions are not allowed across any link in the request chain.

**What transfers directly.** #1, #2, #3, #4, #5, #6, #7, #8, #9, #10 — all of them, plus the philosophical choice "verify, don't trust" extends to the rest of the stack.

**What changes.**

- **Add DPoP (RFC 9449).** A DPoP-bound JWT carries a proof signed by the client's TLS key; stealing the JWT isn't enough — you also need the private key. The web app mints `DPoP <proof> <jwt>` headers instead of `Bearer <jwt>`. The control plane verifies both. This defeats token replay from a different machine.
- **mTLS between services.** The web app ↔ control plane, web app ↔ DB, control plane ↔ DB are all mutually authenticated via certs. No plaintext credentials in `.env`.
- **Workload identity (SPIFFE / SPIRE).** The web app has a SPIFFE identity (`spiffe://yourorg/ns/frontend/sa/web-app`) attested by SPIRE; the control plane and the DB verify it. This replaces client_id + client_secret for *internal* calls and gives continuous, attested workload identity rather than long-lived secrets.
- **Token audience is unambiguous.** Every token has one and only one `aud`. No shared-audience tokens; no "the API gateway accepts any of our services' tokens." If a token leaks, it's only valid for one audience.
- **Strict CSP and SameSite cookies.** The demo's session cookies can be made stricter without breaking auth: `__Host-` prefix, `Secure`, `SameSite=strict`.

**What's added.**

- **Short-lived JWKS-rotation.** If your threat model assumes key compromise, you rotate the signing key hourly with JWKS `kid` rollover. (The demo rotates manually; production rotates automatically.)
- **Per-request token introspection.** Some zero-trust deployments won't accept JWT-at-rest for high-stakes endpoints and require an introspection call to the AS on every request — accepting the latency for the revocation guarantee. See ARCHITECTURE.md §3 ("Why JWT at all?") on the JWT-vs-opaque trade-off.
- **Network policies.** Kubernetes NetworkPolicies, cloud security groups, service mesh authorization (Istio, Linkerd). Only the AS can talk to the user table; only the web app can talk to the resource tables; no path from the internet to the DB at all.
- **Continuous device posture.** For browser-issued tokens, signal device health (browser version, screen-lock status, disk-encryption flag) and reject tokens from postured-failing devices. (Out of token-strictness scope but adjacent.)

**Concrete cut.** Add `python-dpop` to web-app dependencies; emit DPoP proofs on outbound /oauth/token calls and verify inbound ones. Deploy a private CA; switch all service-to-service calls from password auth to mTLS. Run SPIRE alongside the stack; replace `client_secret_basic` for the web-app with a SPIFFE workload identity. Total scope: 2–4 weeks for the protocol work; the operational lift (CA, cert rotation, SPIRE deployment) is heavier than the code.

---

### 2.4 Federated / Multi-IdP (Enterprise B2B)

**The shape.** You sell to enterprises. Each enterprise brings an IdP (Okta, Entra ID, Google Workspace, PingFederate, ADFS). Your AS must accept tokens from all of them, normalize the user identity, and then issue your own access token that your resource servers (DB, internal APIs) can verify locally — without trusting the upstream IdPs at request time.

**What transfers directly.** #1, #2, #3, #4, #5, #6, #7, #8, #9, #10 — all of them. The demo's control plane becomes a *federation broker* between the upstream IdPs and your resource servers.

**What changes.**

- **Inbound OIDC at /authorize.** Instead of the demo's login form, `/authorize` redirects to the upstream IdP's authorization endpoint (per-tenant discovery URL stored in `platform.tenants.idp_config jsonb`).
- **Inbound SAML for the legacy IdPs.** Some enterprises still insist on SAML. Either stand up a SAML → OIDC bridge (`samltest.id`, `auth0` has one, Keycloak can act as a SAML SP and OIDC IdP), or accept SAML `id_token` post-binding directly.
- **Outbound: your own tokens.** After validating the upstream's token (signature against their JWKS, your audience-rewrite if needed), mint your own RS256 access JWT with `sub=normalized_user_id`, `tid=tenant_id`, `groups=[…]`. Resource servers never see the upstream's tokens — only yours.
- **Just-in-time user provisioning.** The first time a user from IdP-X lands, create a row in `platform.users` mapping `external_subject` → your internal `user_id`. Subsequent logins resolve via that mapping.
- **Per-tenant group → role mapping.** Each tenant defines `group:cn=analysts,dc=corp,dc=com` → `senior_analyst` in your app. The mapping is tenant-specific config, not code.

**What's added.**

- **Discovery URLs + JWKS-per-IdP.** Each tenant gets its own JWKS cache entry. Watch for JWKS rotation announcements (some IdPs rotate silently); cache TTL must be short.
- **SCIM provisioning** for user lifecycle. SCIM is the standard way IdPs tell your service "this user was just hired" / "this user was just terminated." Without it, your user table drifts from the IdP's truth source.
- **Federation trust revocation.** When a tenant offboards, you cut the trust (remove from `platform.tenants.idp_config`, revoke active tokens). This requires the same `jti` lookup pattern already in the demo.
- **Name ID and subject claim translation.** Most SAML assertions and OIDC `sub` claims use email or an HRIS id. You need a tenant-specific claim → internal-id mapping; the user table stores both.

**Concrete cut.** Generic OIDC federation: ~2 weeks for a single upstream IdP. Multi-IdP with SAML and per-tenant config: 4–8 weeks plus ongoing IdP-specific support cost. Most "we'll do federation later" projects underestimate that last part. The first IdP is cheap; the fifth is expensive.

---

### 2.5 High-Throughput / Cost Attribution

**The shape.** You operate at scale (10k+ requests/sec, millions of agent invocations/day) and the unit economics matter. You need to attribute every cost — DB queries, LLM tokens, compute-seconds — to the principal that caused it. The audit log isn't just for compliance; it's for billing.

**What transfers directly.** #1, #2, #3, #4, #5, #6, #7, #8, #9, #10 — all of them. The audit log schema already contains `sub` and `act_sub`, which is exactly the cost-attribution key.

**What changes.**

- **Partition `platform.audit_log` by time.** Postgres native time-range partitioning by month. Old partitions can be detached and archived to S3 without breaking queries. Index maintenance stays per-partition.
- **Index by `(sub, ts)` and `(act_sub, ts)`** for fast per-user and per-agent queries. The composite is needed because `sub` alone has low cardinality on a large user base.
- **Stream audit rows to a real-time pipeline.** Kafka / Kinesis / Pub/Sub. Downstream consumers: SIEM, billing, anomaly detection. The DB stays the source of truth; the stream is for everything else.
- **JWKS + jti cache.** Don't look up the JWKS endpoint or `platform.token_records` on every request. In-memory cache keyed by `kid` and `jti` respectively. Sub-millisecond verification path.
- **Connection pooling with GUC awareness.** The demo's `SET LOCAL` pattern is already pool-safe. Production: PgBouncer in transaction mode + per-transaction `SET LOCAL` + the `app_session` role granted only the operations the app needs.

**What's added.**

- **Per-tenant LLM cost ceilings.** A `platform.quotas` table with `(tid, scope, daily_limit)`; the control plane rejects token issuance once a tenant hits it. Prevents one bad client from draining your OpenAI budget.
- **Per-agent cost attribution.** Because `act_sub` is preserved end-to-end, you can answer "how much did agent_copilot_99 cost us last week?" by joining `platform.audit_log` with your LLM-cost ledger on `act_sub`.
- **Read replicas for audit queries.** Application traffic writes; analytics traffic reads. Two replicas minimum in production; offload heavy audit queries to them.
- **Sampling.** At very high volumes, you don't log every token refresh — sample at a configurable rate, log everything destructive. Document the sampling rate in your security policy.

**Concrete cut.** Take the audit log, partition it, set up a stream consumer (Lambda or KCL). Add the LLM cost ledger (one row per LLM call, joined to `act_sub` via the request that emitted it). Build the per-tenant quota check into `/oauth/token` issuance. Total scope: 1–2 weeks for the partitioning + 2 weeks for the cost join + ongoing maintenance of the pipeline.

---

### 2.6 On-Premise / Air-Gapped / Sovereign Cloud

**The shape.** Your customer is a bank, a defense agency, a hospital network, or a sovereign-cloud provider. The auth tier, the data tier, and the application tier all run in a customer-controlled enclave. No internet egress. No shared infrastructure. The "demo" has to come along for the ride, fully self-contained.

**What transfers directly.** All 10 properties. The demo is already air-gap-friendly — there's no required outbound call. What changes is everything around it.

**What changes.**

- **Bring-your-own IdP is mandatory.** The demo's control plane becomes the customer's IdP, not a stub. Plug in their corporate AD/LDAP, or stand up Keycloak / Authentik alongside.
- **Bring-your-own LLM.** Cloud-hosted OpenAI is off the table. Customer runs Azure OpenAI, AWS Bedrock in their account, or a local model server (vLLM, TGI, Ollama). The LLM client code is provider-agnostic already (OpenAI-compatible API).
- **License model.** If you're a vendor shipping this into customer enclaves, you need an offline-licensed binary (no activation calls). Or open-source it. Both are valid; pick before the customer does.
- **Outbound telemetry is replaced with local observability.** No Datadog SaaS, no Sentry, no anything that phones home. Local Prometheus + Grafana + Loki + Tempo. Or the customer's existing observability stack if they have one.
- **Signing key custody.** Customer's HSM, customer's rotation cadence. The control plane reads the key from KMS at startup; rotation triggers a graceful JWKS update.

**What's added.**

- **Update cadence.** Without internet, "patch Tuesday" is a customer-initiated upgrade window. You need release artifacts (containers, signed tarballs), downgrade paths, and an update playbook per customer.
- **Air-gap-specific audit export.** Auditors in this world want a physical-file handoff (S3 bucket with a one-way diode, sneakernet, encrypted drive shipped). Plan the export format up front — JSON Lines is the safest bet.
- **Support model.** On-premise customers want named engineers who can be on-site or on-call, signed escalation paths, and contracts that compensate for outages differently than cloud SLAs.
- **Hardware attestation.** Some customers want the AS to verify the TPM/HSM it's running on hasn't been tampered with (measured boot, TPM quotes). Out of scope for this pattern; mentioned because it will come up.

**Concrete cut.** The demo runs offline today. The real lift is operational: container registry the customer trusts, artifact signing (Sigstore / cosign), upgrade tooling, support runbooks. Most projects underestimate the support runbooks. Plan to write them during the pilot, not after.

---

### 2.7 Edge / Field / Mobile Agent

**The shape.** Agents run on devices that are intermittently connected — phones, field laptops, edge gateways, factory robots. The agent must authenticate when it can, buffer work when it can't, and the audit trail must reconcile once it's back online.

**What transfers directly.** #1, #2, #3, #4, #5, #6, #7, #8, #9, #10 — all of them, with caveats on #5 (RLS requires DB connectivity).

**What changes.**

- **Offline-tolerant token issuance.** The device may not reach the AS for hours. Two patterns: (a) **device-bearer token** — agent has a long-lived DPoP-bound token that doesn't need refresh; revocation is handled by checking `jti` against a *cached* deny-list (push updates to the device when online); (b) **minted-on-device** — the device itself has the signing key material and the AS's JWKS, can verify its own tokens without a round-trip. (a) is more common.
- **Local-first audit queue.** While disconnected, the agent writes audit rows to a local append-only log (LMDB, BoltDB, sqld). On reconnect, replay them into the central `platform.audit_log` with original timestamps and a `replayed_at` flag. Conflict resolution: drop conflicts (a row that already exists with the same `(ts, jti, event_type)`); never overwrite.
- **Read-replica-then-sync.** A subset of the database is replicated to the device (often via CRDTs or read-only snapshots). RLS runs locally; mutations queue for replay; conflicts resolve by server authority on reconnect.

**What's added.**

- **Device identity binding.** Token is bound to the *device* (DPoP key, device certificate, Secure Enclave key). Stealing the token requires stealing the device.
- **Loss / theft procedures.** When a device is reported missing, push the deny-list and rotate any token it held. Belt-and-suspenders.
- **Bandwidth- and energy-aware sync.** Don't try to replay 10k audit rows over a satellite link. Compress; batch; retry with backoff.

**Concrete cut.** Usually not "build from this demo" — usually "build a new agent runtime that uses this demo's patterns." The SSO + delegation model transfers; the offline primitives are new.

---

## 3. Products and Services for AI Agents

Different problem set. The previous section is about deploying a system *with* agents. This section is about building a *product whose customers are agents (or whose customers have agents).*

The product categories below are ordered by how close to market they are and how directly this demo's patterns apply.

### 3.1 MCP Server with User Context

**What it is.** You're building an [MCP server](https://modelcontextprotocol.io/) — Anthropic's protocol standardizing how AI agents connect to tools and data. Today most MCP servers run in the user's desktop context (Claude Desktop, Cursor). Tomorrow they run in shared infrastructure with multiple agents connecting.

**The identity gap.** A naive MCP server doesn't know who the user is — the agent calls the MCP server, the MCP server returns data. Two agents (one for the user, one autonomous) calling the same server look identical. You can't enforce per-user authorization; you can't audit who the agent was acting for.

**How this demo fits.**

- The MCP server *is* an OAuth 2.1 resource server in this model. It exposes `/.well-known/oauth-protected-resource` (RFC 9728), accepts bearer tokens, and verifies them via JWKS — exactly the pattern in the demo's web-app.
- For delegation: the user's agent presents a `sub=user_X, act.sub=agent_Y` JWT. The MCP server's tool executes under that identity. RLS at the MCP server's backend gives per-user row filtering without the MCP server trusting the agent.
- The MCP server can also *exchange* a token for the user-specific tool execution via RFC 8693 — useful when the agent holds a long-lived token and the MCP needs a per-tool scoped one.

**Concrete shape.**

```text
User → Browser-based Claude (via MCP) → MCP server (your product)
                                            │
                                            ├─ Verify Bearer JWT (sub=user, act.sub=agent)
                                            ├─ Run tool with SET LOCAL user_id, actor_id
                                            └─ Audit row: principal=user, actor=agent
```

**What you'd build.** Your MCP server has the same shape as the demo's web-app: FastAPI / Express, JWKS cache, the `run_with_identity()` pattern, an RLS-aware backend. The protocol glue (MCP JSON-RPC over stdio / HTTP / SSE) sits in front of the same handler shape.

**What's missing.** MCP-client identity attestation is still maturing. Today most MCP clients are desktop apps where the "user" is implicit. As soon as MCP has a real OAuth client story, you'd adopt it and this demo's RFC 8693 story fits cleanly.

---

### 3.2 Agent Platform / Marketplace

**What it is.** You're building a platform where many agents live — think an "App Store for agents" where customers browse, install, and delegate to agents from multiple vendors. Examples in the wild: Glean, Moveworks, Lettria, Adept, and the "GPT Store" precedent.

**The identity problem.** A user installs 12 agents. Each agent wants to call your APIs on the user's behalf. Without per-agent scoping, agent A can read agent B's data; the audit trail says "user did it" without naming which agent; revoking agent A doesn't help because vendor B's agent still has scope.

**How this demo fits.** The platform's authorization server is the demo's control plane. Each vendor's agent is registered as an OAuth client (in `platform.clients` with `client_id=agent_<vendor>_<id>`, `client_type=agent`, vendor-specific `default_scopes`). When a user installs an agent:

1. Vendor → your AS: `POST /oauth/token` with `grant_type=client_credentials` for the agent's bootstrap identity.
2. User → your UI: clicks "install agent X" → triggers `POST /oauth/token` with `grant_type=token-exchange`, the user's JWT as subject, the agent's client_id as actor. Your AS mints a per-(user, agent) JWT with `act.sub=agent_id` and scopes downscoped.
3. Agent calls your APIs with that token. Your RLS at the data layer filters by `user_id` and treats `actor_id=agent_X` distinctly.
4. User can revoke per-agent via `POST /oauth/revoke jti=<agent token>`. The audit log shows "user_X installed agent_Y at Z, called tools A B C, revoked at W."

**Concrete shape.**

| Actor | In this demo's terms |
|---|---|
| Your platform | The control plane + the database with RLS |
| The user | Principal (`sub`) |
| The agent vendor's runtime | Headless client (`client_id`) |
| The agent | `act.sub` (the delegating actor) |
| Vendor dev account | A separate OAuth scope (`vendor:publish`) for uploading agent manifests |

**What you'd build.** A manifest format (like MCP's tools/capabilities schema, but with `default_scopes` and `data_access_tags`). A review workflow before an agent can be published (auditor reviews requested scopes). A per-user, per-agent revocation UI. An analytics dashboard that ranks agents by `act_sub` × usage.

**What's missing.** Per-agent cost attribution is hard when vendors run their agents on their own infra. The pattern works best when *you* host the agents so you have the audit row.

---

### 3.3 Agent Observability / Audit Product

**What it is.** A standalone product — or a feature of an existing one — that gives customers visibility into what their agents are doing. "Which agents touched customer PII this week?" "What did agent X do at 2am?" "Did agent Y's daily run cost $30 or $300?"

**How this demo fits.** Take a step back: the demo's `platform.audit_log` is *literally* what such a product would store. The product is a query / dashboard / alerting layer on top of a similar schema:

| Audit column | Product feature |
|---|---|
| `ts, sub, act_sub` | Per-user timeline: "user_123's agents did 47 things today" |
| `event_type='rls_block'` | Anomaly detection: spike in RLS blocks = suspicious agent or compromised key |
| `event_type='token_*'` | Token hygiene: stale tokens, revoked-without-replaced, abnormal client mix |
| `agent_id` | Per-agent cost rollup + per-agent permission audit |
| `details jsonb` | Free-form extension for vendor-specific events (RAG retrievals, tool calls, etc.) |

**What you'd build.** Move the audit log to a real-time stream. Build the query layer in ClickHouse or BigQuery or DuckDB-WASM in the browser. Ship a few canned dashboards (per-user, per-agent, per-role) plus a SQL query interface for security teams. Add SIEM export (Splunk, Panther, Datadog Cloud SIEM).

**Concrete shape.** A customer enables the product on their data tier. Your collector (sidecar / extension to their app) emits RFC 8693-shaped events. You store them; you query them; you alert on them. The customer doesn't have to know RFC 8693 to use the product; they enable the SDK and get audit.

**What's missing.** Cross-system attribution. Most agent runs span multiple tools (browser, file system, APIs, DBs). Each tool emits audit but none know about the others. The next frontier: an open protocol for "session-id propagation" so an agent's audit trail across systems stitches into one timeline. (Drafted in the same family as W3C Trace Context.)

**Why this could be a category.** Today almost no team has this view. It will become table stakes for any regulated-industry agent deployment. The product opportunity is *before* the regulated buyers demand it.

---

### 3.4 BYO-Agent API (Third-Party Agents Call Your API on Behalf of Your Users)

**What it is.** You operate an API (payments, CRM, banking, healthcare records). Third-party agents want to call it on behalf of your users — sometimes authorized by the user directly, sometimes authorized by the user's first-party app, sometimes authorized by your customer's enterprise admin. Think: "Plaid but for agents," or "Stripe Connect but the connected account is an AI agent."

**The identity problem.** Three parties: user, agent, your API. None of them fully trust the others. The user wants to grant agent X read-only access to their account. The agent doesn't want your API to learn too much about how it operates. You want per-user, per-agent authorization with audit.

**How this demo fits.** Your API is the resource server. You stand up (or contract with) an authorization server that:

- Registers each third-party agent as an OAuth client with `client_type=agent`, per-agent `default_scopes`, and an `is_delegatable` flag.
- When the user wants to delegate to an agent: your UI runs an RFC 8693 exchange against the agent's identity, mints a user-scoped agent token with `act.sub=agent_id`, scopes downscoped.
- Your API verifies the token, runs with `SET LOCAL user_id, actor_id`, RLS enforces row-level + agent-type.

**Concrete shape.**

```
User → Vendor's agent → POST /oauth/token (RFC 8693, your AS)
                       │
                       └─ Returns: {sub: user_X, act.sub: vendor_agent_Y, scope: read:*}

Vendor's agent → your API:  Bearer <token>
                                  │
                                  ├─ Verify: RS256, JWKS, iss, aud, jti, exp
                                  ├─ DB: SET LOCAL app.user_id=user_X, app.actor_id=vendor_agent_Y
                                  └─ Query runs under RLS — vendor_agent_Y can only see user_X's rows
```

**The hard parts.** Rate-limiting by `(user, agent)` pair. Cost-attribution back to the agent vendor ("vendor Y used your API $X this month"). Vendor onboarding + scope review (do you trust vendor_Y with read:billing?). Pricing models that work for high-frequency agent traffic (per-request vs bundle).

**What you'd build.** A vendor SDK that wraps the RFC 8693 + JWT verification flow. A vendor dashboard: live traffic, error rates, cost. Admin review workflow for new vendors. A "kill switch" UI for users to revoke per-vendor.

**Real-world analogue.** Plaid's Link, Stripe's Connect, Google's "Sign in with Google for AI agents" (forthcoming), OpenAI's plugin auth model (deprecated but pattern-relevant), and others. The patterns all converge on RFC 8693 + JWKS + RLS.

---

### 3.5 Multi-Agent Orchestration (Nested Delegation)

**What it is.** A user delegates to an orchestrator agent. The orchestrator delegates to specialist sub-agents. The sub-agents run tools against your API or DB. Each delegation step needs the same principal/actor discipline. The audit must read like a call graph: *user → orchestrator → research_agent → tool_call*.

**How this demo fits — with caveats.** The demo's `act` claim supports nesting in principle (RFC 8693 allows `act` to be an object tree). The demo's code currently collapses `act` to one level. Production orchestration needs the full tree.

**What you'd build.**

- **Nested `act` chains.** Each delegation passes the existing `act` and adds a new layer. The final JWT that hits your DB has:
  ```
  {
    "sub": "user_123",
    "act": {
      "sub": "orchestrator_main",
      "act": {
        "sub": "research_specialist",
        "act": {
          "sub": "browser_browser_agent"
        }
      }
    }
  }
  ```
- **`act_chain` helper in the DB.** The audit log's `act_sub` column should arguably be `act_chain text[]` or a `jsonb` path. PG/RLS helpers walk the chain and check "does the *root* principal own this row?"
- **Capability narrowing at each step.** Orchestrator can invoke specialist X; specialist X has scopes `[read:web, read:db]`; specialist X delegates to browser-tool with scope `[read:web]` only. The intersection discipline applies at every hop.
- **Audit fidelity.** One row per logical action, with the full `act_chain` so an investigator can reconstruct the path. Volume is a concern — a busy multi-agent system produces 10x the audit rows of a single-agent one. Plan partitioning and sampling accordingly.

**Concrete shape.**

```sql
-- Audit row produced by an orchestrator's specialist's tool call
{event_type: tool_call, sub: user_123, act_sub: research_specialist, act_chain: [orchestrator_main, research_specialist], result: success, details: {...}}
```

**Why this matters now.** LangGraph, CrewAI, and AutoGen are all shipping multi-agent primitives. Without an audit story, the products are gated out of regulated deployments. The first platform that builds this well will own the regulated-agent market.

---

### 3.6 Agent Identity & Permission Broker (the OAuth-of-Agents idea)

**What it is.** A new product category: a permission broker that sits *between* every agent and every tool/data source. User says "agent X can read my CRM but not write to my email." The broker enforces that. Tools only ever see the broker; agents only ever see the broker. Everything else is between them. The closest analogues: Stripe's API for payments, Auth0 for user login, Plaid for financial auth.

**How this demo fits.** *This demo's pattern is the prototype of the broker.* Three principals become a permission taxonomy. RFC 8693 becomes the broker's primary protocol. RLS at the resource becomes the broker's enforcement layer (or you stand up a broker that fronts *other people's* resources and implements RLS at a proxy layer in front of their data).

**What you'd build.**

- **Token issuance.** The broker is the AS. Tools that talk to the broker are OAuth 2.1 clients. Tools that *don't* (because you can't modify them) can be configured with bearer tokens issued by the broker, scoped per-user-per-agent-per-tool.
- **Policy engine.** OPA, Cedar, or your own — the broker evaluates "should this agent be allowed to do X for this user on this resource?" before issuing the token. Policies are user-readable and version-controlled.
- **Audit fan-out.** Every grant, every action, every revoke is logged centrally and exportable to the user's SIEM.
- **Resource adapters.** The broker needs to enforce at the resource. If the resource is the user's Postgres DB, the broker issues an RLS-bypass credential and a delegated agent credential, both with their own scope; the user runs a small adapter (`pgaudit`, `pg_tokenizer`) in their DB that verifies and applies the GUCs. If the resource is SaaS-X without an API for delegation, the broker is limited to issuing scoped-to-SaaS-X-API tokens and trusting SaaS-X's own enforcement.
- **Cost & rate-limit layer.** The broker is the natural place to track per-agent spend and enforce per-agent limits; "agent_Y can spend $20/day on this user's behalf."

**Concrete shape.**

```
                 ┌─────────────────────┐
                 │  Permission Broker  │
                 │   (your product)    │
                 │                     │
   User ─────────┤  ─ policies ─       │
                 │  ─ token exchange ─ │──────────── SaaS-X (no SDK changes)
   Agent ────────┤  ─ audit fan-out ─  │────┌─────── DB (RLS + GUCs)
                 │  ─ cost & quotas ─  │    └─────── Files (scoped tokens)
                 └─────────────────────┘
```

**What you'd build on top of this demo.** Take the demo's control plane, lift the in-memory auth-code cache into Redis, replace the demo's DB with a managed-PG (or Aurora / CockroachDB), and you've got the AS+audit backbone. The differentiator isn't the AS — it's the policy engine + the resource adapters + the developer experience for connecting new resources.

**Why this could matter.** The hardest unsolved problem in deploying agents in the enterprise is *least-privilege at scale* — who has access to what, which agents, when. Most teams will buy, not build. A well-built broker is a meaningful exit-quality business. The OAuth identity layer is a commodity; the broker is the value-add.

---

## 4. Decision Matrix: Start With X if You're Y

| Your situation | Where to begin | Why |
|---|---|---|
| "I just want to know if this pattern is right for us" | Run this demo, read ARCHITECTURE.md §1–§3 | Decides fit in a day. See §2 first row of each archetype. |
| "We're a B2B SaaS adding agent support to our existing app" | §2.1 Multi-tenant SaaS | Most common starting point. Schema changes (add `tid`) are small; tenant provisioning UI is the lift. |
| "We're regulated — HIPAA / SOC 2 / FedRAMP customer tomorrow" | §2.2 Regulated Industry | Audit-log immutability is the hard part; do that first. Token TTL changes are cheap. |
| "Our enterprise customers have their own IdPs" | §2.4 Federated / Multi-IdP | First IdP is cheap. Plan for the operational cost of the fifth. |
| "We're an MCP server builder" | §3.1 MCP Server with User Context | The demo's web app is your reference implementation; the protocol layer is the new code. |
| "We're building an agent platform / marketplace" | §3.2 Agent Platform | Use this demo's control plane as the start; add the vendor manifest format and review workflow. |
| "We're building observability / audit for agents" | §3.3 Agent Observability | Take the audit-log schema; build the query layer; sell the dashboard. |
| "Third-party agents will call our API" | §3.4 BYO-Agent API | Hybrid: 3.1's verifier + 3.2's onboarding. Vendor SDK is the focal point. |
| "We have multi-agent products (orchestrator → specialists)" | §3.5 Multi-Agent Orchestration | Nested `act` and a `pg_tokenizer`-style GUC helper. Open protocol problem. |
| "We want to *be* the auth layer for the agent economy" | §3.6 Agent Identity & Permission Broker | Largest scope, longest build. This demo's control plane is your seed. |

The matrix's most underrated row is the first: **most teams should run the demo and read §1–§3 of ARCHITECTURE.md before deciding.** The decision takes a day. The wrong choice takes a year.

---

## 5. Open Questions

The agent-identity space is moving fast. Things this demo deliberately doesn't decide yet, with current thinking:

**Are JWTs the right token format for agents?** *For now, yes.* Asynchronous verification (no AS round-trip) is necessary when the resource server is a database. The demo's choice holds. Watch PASETO for greenfield systems; watch DPoP for sender-binding. See ARCHITECTURE.md §3 ("Why JWT at all?") for the full trade-off matrix.

**How do we prove the LLM was the one running, not a human pretending to be the LLM?** *We don't, yet.* The actor identity in this demo is the *agent runtime*, not the model invocation. If a human types into Claude to ask it to do X, the actor is "claude-code" — there's no claim that the model produced the answer vs a human pasted it. As AI-vs-human-attribution becomes a regulatory requirement (deepfake laws, election integrity), the audit column model needs to extend. Standardization efforts (C2PA, content authenticity) are early.

**How do we handle agents that fork themselves?** *Open question.* An agent can spawn a sub-agent. RFC 8693's `act` claim supports nesting in principle; the demo's code doesn't. The harder question is what to do if an agent spawns 10,000 sub-agents — at what point are you running a botnet? The detection is the hard part; the model supports it.

**How do we get audit rows for offline agent work (devices, edge)?** *See §2.7.* Pattern: local append-only log + replay. Not novel, but under-supported by current tools.

**Will there be a standard session-id format that crosses systems?** *No standard yet.* Right now you have W3C Trace Context (tracing, not auth), OpenTelemetry (telemetry, not auth), and a dozen vendor-specific agent-session-id proposals. The agent economy would benefit from a standard that says "these 50 audit rows are part of one logical agent session, principal X, started at T." Several efforts underway; none ratified.

**Will the agent-as-a-service model dominate, or agent-as-a-toolkit?** *Predictions vary.* Some platforms (OpenAI, Anthropic) host the agent runtime. Some (LangChain, CrewAI) ship agent *toolkits* that customers run in their own infra. This demo works in both models — the question is where the *audit log* lives. Hosted: the platform owns it. Toolkit: the customer's stack owns it. The patterns are identical; the operational ownership is the dividing line.

**How do we test that our RLS policies are correct?** *Mostly by negative tests.* Write tests that try every disallowed principal/actor/scope combination and assert BLOCKED. The demo's tests directory has the shape; production needs this entire category formalized. Property-based testing (Hypothesis, fast-check) helps — generate random (principal, actor, row, scope) tuples and assert policy denies every that should be denied.

**What about non-determinism in the LLM?** *Out of scope of identity, but affects audit.* An LLM can produce different tokens on different runs for the same prompt. The audit row records the *request* and the *outcome*; the *reasoning* in between is opaque. For regulatory scenarios requiring explainability (EU AI Act high-risk systems), this means the reasoning trace must be captured and stored alongside the audit row. It's a different problem from identity; it's the same architectural point: *the artifacts you don't capture, you can't audit.*

---

If you've read this far and see a deployment shape or product category missing, open an issue or send a PR. The agent-identity space is moving, and this document should move with it.
