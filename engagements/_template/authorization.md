# Engagement Authorization & Rules of Engagement — <slug>

> The human-facing engagement record. The machine-readable scope the tooling
> enforces is `scope.yaml` next to this file. **No active testing may begin until
> the Authorization section below names a valid basis and (for client work) the
> signed document reference is recorded.**

## 1. Engagement
| Field | Value |
|---|---|
| Engagement slug | `<slug>` |
| Client / owner | `<client org, or "self">` |
| Type | client / bug-bounty / ctf / self-owned |
| Operator (tester) | <operator email> |
| Test window | `<start> – <end>` (`<timezone>`) |
| Tester source IP(s) | `<egress IPs>` (share with client for allowlisting + log attribution) |

## 2. Authorization (the key section)
- **Basis:** `<self-owned ownership / signed SOW + RoE / bug-bounty program scope>`
- **Signed document reference:** `<path / DocuSign id / ticket / program URL>`
- **Signed by (client):** `<name, title, date>`
- **Authorizes:** the targets in §3 `in_scope`, during the §1 test window, by the
  named operator, under the §4 rules.
- For **client** engagements this must reference an executed authorization
  (SOW/RoE/penetration-test authorization letter). Self-owned: confirm ownership.
  Bug-bounty: link the program's scope + rules page.

## 3. Scope (summary — authoritative machine copy in `scope.yaml`)
**In scope:**
- `<hosts / domains / CIDRs / apps>`

**Explicitly out of scope:**
- `<excluded hosts, third-party infra, shared SSO/payment providers>`

## 4. Rules of Engagement
- Non-destructive by default; proof-of-concept only.
- Prohibited: DoS/stress, social engineering/phishing, physical (unless explicitly contracted).
- Data handling: on real user data, capture one redacted proof then STOP; no exfiltration; redact PII/secrets in all artifacts.
- Intensity / rate-limiting: `<agreed limits>`.
- Permitted intrusive actions (if any, contracted): `<e.g. authenticated testing, specific exploit confirmation>`.
- Testing windows / blackout periods: `<...>`.

### 4a. Authenticated testing (only if login testing is in scope)
- **Test accounts attested:** `<yes/no>` — each role in `roles.json` is a
  NON-PRODUCTION / sandbox account provisioned by the client. (Required before the
  authenticated phase may run.)
- **Credentials stored OUT OF TREE** at `$PENTEST_AUTH_HOME/<slug>/roles.json`
  (default `~/.redan/auth/<slug>/`), secrets via env vars where possible.
- **Write/mutation testing:** `<read-only | approved>` — if approved, set
  `mutation_testing: approved` in scope.yaml; otherwise authenticated testing is
  READ-ONLY (enforced by the mutation-gate hook).
- **Roles & entitlements (authz_model):** list each test role and what it is
  INTENDED to access (own-only / org-scoped / tenant-scoped / global) and its
  tenant/org — so cross-account access is only flagged when it crosses a real
  boundary. Multi-tenant tests use two accounts in DIFFERENT tenants.
- **Synthetic objects:** the client seeds the specific object IDs each role owns
  (`owned_objects`) so IDOR proof never reads a real third party's data.
- **Rollback / blast-radius:** test env is `<snapshot-restorable? backed up?>`;
  any observed real mutation/side-effect → STOP + notify the emergency contact.

## 5. Contacts
| Role | Name | Channel |
|---|---|---|
| Client primary | `<name>` | `<email/phone>` |
| Technical POC | `<name>` | `<email/phone>` |
| **Emergency stop** | `<name>` | `<24/7 channel>` |

If production impact is observed, STOP and notify the emergency contact immediately.

## 6. Confidentiality / NDA
- NDA in place: `<yes/no + reference>`.
- Report classification: Confidential. Evidence + reports stay under
  `engagements/<slug>/` (gitignored) and are handled per the NDA.

## 7. Pre-engagement checklist
- [ ] Authorization basis recorded (§2) and, for client work, signed doc referenced.
- [ ] Scope agreed and entered in `scope.yaml` (in/out).
- [ ] Test window + tester source IPs shared with client.
- [ ] Emergency-stop contact confirmed reachable.
- [ ] NDA executed (if applicable).
- [ ] This engagement set active: `cp engagements/<slug>/scope.yaml scope.yaml`.

## 8. Sign-off
| Party | Name | Date |
|---|---|---|
| Client authorizer | | |
| Operator | <operator email> | |
