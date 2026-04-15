---
layout: post
title: " AI Findings: Permissions Boundary Bypass Analysis"
date: 2026-04-15
categories: aws security findings iam
---

## Results

### Permissions Boundary Bypass Analysis — `platform-admin-boundary-production`
Policy & Config | 2026-04-15 | 123456789012 | SCP: UNKNOWN

**Scope:** 1 boundary policy, 1 bounded role (`platform-restricted-admin-production`), 19 custom roles, 10 SLRs, 0 EC2 instances, 0 Lambda functions | **Regions:** ap-southeast-2 (primary), IAM global | **Gaps:** SCPs unreadable (AccessDenied) — findings may be mitigated by org-level SCPs  
**Suppressions:** None

---

#### F1: Unrestricted `iam:PassRole` in boundary · `CRITICAL` · `CONFIRMED 5/5`
**Resource:** `arn:aws:iam::123456789012:policy/platform-admin-boundary-production`  
**Claim:** `adhoc-20260415-boundary-passrole-unrestricted`

The boundary allows `iam:PassRole` with `Resource: "*"`. This means the bounded principal can pass **any role in the account** to any compute service the boundary also permits (Lambda, EC2). PassRole is the single most dangerous IAM action to leave unrestricted in a boundary — it's the mechanism that enables escaping the boundary entirely. The boundary should scope PassRole to a specific set of approved execution role ARNs.

**SCP coverage: Unknown** — this account is in an AWS Organization but SCPs could not be read (AccessDenied on organizations:ListPolicies). An SCP may deny the actions flagged here, which would reduce or eliminate this risk. Provide SCP documents for cross-referencing, or verify from the management account.

---

#### F2: Boundary bypass via `lambda:*` + `iam:PassRole *` · `CRITICAL` · `CONFIRMED 5/5`
**Resource:** `arn:aws:iam::123456789012:role/platform-restricted-admin-production`  
**Claim:** `adhoc-20260415-boundary-lambda-bypass`

The boundary grants `lambda:*` (full Lambda management) **and** `iam:PassRole` on `*`. This is a complete boundary escape. The bounded role can:

1. Call `lambda:CreateFunction` with any Lambda-trusted role as the execution role
2. The Lambda function executes as that role, **outside the boundary** — boundaries only apply to the principal they're attached to, not to roles passed to services

Three Lambda-trusted execution roles exist without boundaries:
- `svc-data-processor-exec-production` — DynamoDB full CRUD (`*`), S3 read (`*`), CloudWatch Logs
- `svc-reporting-api-exec-production` — S3 read (scoped to `platform-internal-reports-123456789012`), DynamoDB read, CloudWatch Logs
- `svc-data-processor-secure-exec-production` — no policies attached (currently inert)

The boundary does not include `dynamodb:*` in its allow list, yet via this bypass the bounded role gains DynamoDB write access to every table in the account. The boundary's intent (restrict to ec2/s3/logs/cloudwatch/lambda) is completely undermined.

**SCP coverage: Unknown** — same disclaimer as F1.

---

### Attack Chains

#### Attack Path 1: Boundary escape via Lambda PassRole delegation
**Severity:** CRITICAL  
**Chain:** Claim `adhoc-20260415-boundary-passrole-unrestricted` → Claim `adhoc-20260415-boundary-lambda-bypass`  
**Exploitability:** IMMEDIATELY EXPLOITABLE

1. Attacker compromises an EC2 instance assuming `platform-restricted-admin-production` (trust policy allows `ec2.amazonaws.com`)
2. Boundary constrains the session to ec2/s3/logs/cloudwatch/lambda + limited IAM reads + PassRole
3. Attacker calls `lambda:CreateFunction`, sets execution role to `svc-data-processor-exec-production` (`iam:PassRole *` permits this)
4. Attacker calls `lambda:Invoke` — Lambda executes as `svc-data-processor-exec-production`, which has **no boundary**
5. Lambda code reads/writes all DynamoDB tables and reads all S3 buckets — permissions the boundary was designed to block

**Impact:** Full DynamoDB CRUD on every table in the account + S3 read on every bucket. The boundary provides zero protection against this path. An attacker operating within the "restricted admin" boundary can exfiltrate or modify application data in DynamoDB without detection by boundary-aware monitoring.

---

### Impact

**Data at risk:** All DynamoDB table contents (customer data, application state), all S3 object reads  
**Services at risk:** DynamoDB (full CRUD via bypass), Lambda (used as escalation vehicle)  
**Exposure:** Immediate — no additional permissions or conditions required  
**Compliance:** CIS AWS Benchmark 1.16 (ensure IAM policies are attached only to groups or roles — boundary scoping), SOC2 CC6.3 (least privilege)  
**Amplifying:** PassRole unrestricted to `*`, `lambda:*` is full wildcard, no boundary on target execution roles, boundary is the sole control (no inline Deny guardrails)  
**Mitigating:** No EC2 instances currently use this role (RoleLastUsed is empty), `svc-data-processor-secure-exec-production` has no policies attached  
**Unknown:** SCP coverage (may restrict PassRole or Lambda at org level), whether other accounts have roles trusting this account

---

### Blast Radius

| Resource Type | Scope | Access Level | Condition |
|:-------------|:------|:-------------|:----------|
| DynamoDB tables | All tables in account (`*`) | Read/Write/Delete | Via Lambda with `svc-data-processor-exec-production` |
| S3 buckets | All buckets (`*`) | Read | Via Lambda with `svc-data-processor-exec-production` |
| S3 bucket (scoped) | `platform-internal-reports-123456789012` | Read | Via Lambda with `svc-reporting-api-exec-production` |

---

### Recommendations

| Priority | Action | Effort | Risk Reduction |
|:---------|:-------|:-------|:---------------|
| P0 | **Scope PassRole to specific role ARNs** — Replace `"Resource": "*"` in the boundary's `AllowRoleManagement` statement with explicit ARNs: `"Resource": ["arn:aws:iam::123456789012:role/svc-data-processor-exec-production", "arn:aws:iam::123456789012:role/svc-reporting-api-exec-production"]` | Low | Eliminates unrestricted role delegation — the primary bypass enabler |
| P0 | **Restrict `lambda:*` to non-management actions** — Replace `"lambda:*"` with `["lambda:InvokeFunction", "lambda:GetFunction", "lambda:ListFunctions"]`. Remove `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration` from the boundary unless this role needs to deploy Lambda | Low | Eliminates Lambda as a boundary escape vehicle — bounded role can invoke but not create/modify functions |
| P1 | **Add boundaries to Lambda execution roles** — Attach `platform-admin-boundary-production` (or a tighter policy) to `svc-data-processor-exec-production` and `svc-reporting-api-exec-production` as their PermissionsBoundary | Med | Defense-in-depth — even if PassRole is exploited, the target role is also bounded |
| P1 | **Add explicit Deny guardrail** — Add an inline Deny policy to the restricted-admin role blocking `iam:PassRole` to any role NOT in an approved list. This provides a second layer independent of the boundary | Med | Belt-and-suspenders — survives boundary policy version updates that might accidentally widen PassRole scope |
| P2 | **Provide SCP documents for cross-reference** — Run `aws organizations list-policies --filter SERVICE_CONTROL_POLICY` from the management account and share the results | Low | Confirms whether org-level controls already mitigate these findings |

---

### Confidence: 5/5

All findings verified with direct CLI evidence showing exact policy documents. PassRole bypass is a well-documented IAM escalation pattern. | **Verdict:** Accept as-is — implement P0 recommendations immediately. Verify SCP coverage from the management account to determine if org-level controls provide any mitigation.
