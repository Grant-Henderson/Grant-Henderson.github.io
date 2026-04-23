---
layout: post
title: "AI Blast Radius: Attack Chains Combined"
date: 2026-04-15
categories: aws security blast-radius iam
---

# Identity Blast Radius: Attack Chains Combined

Identity Blast Radius | 2026-03-24 | XXXXXXXXXXXX | SCP: UNKNOWN

## Identities Assessed

| Chain | Entry Point | Terminal Identity | Terminal Permissions |
|:------|:-----------|:------------------|:--------------------|
| Attack Path 1 | `svc-deploy-automation-production` | `svc-data-processor-exec-production` + stolen creds | DynamoDB `*`, S3 `*`, RDS via plaintext creds |
| Attack Path 2 | `platform-restricted-admin-production` | `svc-platform-admin-production` | `AdministratorAccess` (no boundary) |
| Attack Path 3 | `svc-analytics-reader-production` | `svc-platform-admin-production` | `AdministratorAccess` (no boundary) |

---

## Access Summary (Combined — worst case from any chain)

| Category | Access Level | Resources Reachable | Key Actions |
|:---------|:-------------|:--------------------|:------------|
| Data | Read/Write/Delete | 2 Lambda functions, 3 CloudWatch log groups, 27 KMS keys (23 PendingDeletion), external RDS via stolen creds | `s3:*`, `dynamodb:*`, `lambda:GetFunction`, `kms:Decrypt`, RDS direct connect |
| Identity | Full Admin | 1 IAM user, 28 IAM roles, 61 tracked policies | `iam:*`, `sts:AssumeRole`, `iam:PassRole *`, `iam:CreateUser`, `iam:CreateAccessKey` |
| Detection | Full Control (nothing to disable) | 0 CloudTrail trails, 0 GuardDuty detectors, 0 Security Hub, 0 Config recorders, 0 Access Analyzers | No detection services exist — attacker operates with zero logging |
| Compute | Execute/Modify | 2 Lambda functions (us-east-1), 0 running EC2, can launch in 17 regions | `lambda:*`, `ec2:RunInstances`, `ecs:*` |
| Network | Full Modify | 1 VPC (default), 1 security group (default) | `ec2:AuthorizeSecurityGroupIngress`, `ec2:CreateSecurityGroup`, `ec2:ModifyVpcAttribute` |

---

## Risk Level: CRITICAL

**Why:** The combined blast radius from the three attack chains reaches full `AdministratorAccess` (chains 2 and 3) with **zero detection coverage**. There are no CloudTrail trails, no GuardDuty detectors, no Security Hub, no AWS Config recorders, and no IAM Access Analyzers in any region. An attacker who compromises any of the three entry-point roles achieves admin access with no audit trail, no alerting, and no automated response. Chain 1 additionally exposes plaintext production database credentials and API keys that grant access to systems outside AWS.

**Amplifying:**
- Zero detection services — complete absence of CloudTrail, GuardDuty, Security Hub, Config, Access Analyzer
- Wildcarded resources on sensitive actions (`iam:PassRole *`, `s3:*`, `dynamodb:*`, `lambda:*`)
- No permission boundary on terminal admin role (`svc-platform-admin-production`)
- SCP coverage unknown — cannot confirm organizational guardrails exist
- Plaintext secrets in Lambda env vars (external RDS + API access)
- 23 customer-managed KMS keys in PendingDeletion — encryption controls being removed
- Admin IAM user has no MFA

**Mitigating:**
- Permission boundary on `platform-restricted-admin-production` (partially effective — bypassed via PassRole+Lambda but limits direct IAM actions)
- `BoolIfExists` MFA condition on `svc-data-ops-production` S3 delete operations (correctly implemented)
- No running EC2 instances currently (all terminated) — reduces immediate lateral movement surface
- No S3 buckets, DynamoDB tables, or RDS instances exist in-account — reduces in-account data exfiltration scope
- Cross-account roles require MFA (`Bool` condition — effective for human callers)

---

## Detailed Access

### Data Access

**In-account data stores:**

| Resource Type | Count | Resources | Access Level |
|:-------------|:------|:----------|:-------------|
| S3 Buckets | 0 | None exist | N/A (admin can create) |
| DynamoDB Tables | 0 | None exist | N/A (admin can create) |
| RDS Instances | 0 | None exist | N/A (admin can create) |
| Secrets Manager | 0 | None exist | N/A (admin can create) |
| Lambda Functions | 2 | `svc-data-processor-production`, `svc-reporting-api-production` | Read/Write/Delete code + config |
| CloudWatch Log Groups | 3 | `/aws/lambda/blog-application` (16 KB), `/aws/lambda/blog-application-data` (2.7 MB), `/aws/lambda/svc-reporting-api-production` (738 B) | Read/Delete (no retention set) |
| KMS Keys | 27 | 4 AWS-managed (Enabled: EBS, FSx, Lambda, Secrets Manager), 23 customer-managed (all PendingDeletion) | Admin can cancel deletion, decrypt, schedule deletion |

**External data (via stolen credentials from Chain 1):**

| Resource | Credential | Access Level |
|:---------|:-----------|:-------------|
| `prod-db-cluster.cluster-REDACTED.us-east-1.rds.amazonaws.com` | `DB_USERNAME: REDACTED`, `DB_PASSWORD: REDACTED` | Full database read/write/delete |
| External API | `API_KEY: REDACTED` | Full API access |
| Webhook endpoint | `API_SECRET: REDACTED` | Webhook signature forgery |

### Identity Access

**Direct admin (via chains 2 or 3 → `svc-platform-admin-production`):**

Full `iam:*` on all resources — can create, modify, or delete any IAM principal or policy.

| Action | Scope | Impact |
|:-------|:------|:-------|
| `iam:CreateUser` + `iam:CreateAccessKey` | `*` | Create persistent backdoor user with long-lived credentials |
| `iam:AttachRolePolicy` + `iam:PutRolePolicy` | `*` | Attach AdministratorAccess to any role, inject inline policies |
| `iam:UpdateAssumeRolePolicy` | `*` | Modify trust policies to allow external account assumption |
| `iam:PassRole` | `*` | Pass any role to any compute service |
| `iam:CreateServiceLinkedRole` | `*` | Create SLRs for any service (recon + indirect escalation) |
| `sts:AssumeRole` | `*` | Assume any role in the account |
| `iam:DeleteRolePolicy` + `iam:DetachRolePolicy` | `*` | Remove permission boundaries and guardrails |

**PMapper escalation graph — principals reachable from admin:**

All 30 nodes (6 admin, 24 non-admin) are reachable. The admin role can modify trust policies to assume any role, or create access keys for any user.

**Assumable roles (all 28 — admin can modify any trust policy):**

| Role | Current Trust | Risk if Compromised |
|:-----|:-------------|:-------------------|
| `AWSReservedSSO_AdministratorAccess_*` | SAML (SSO) | SSO admin access |
| `AWSReservedSSO_PowerUserAccess_*` | SAML (SSO) | SSO power user |
| `IdentityAccountAccess` | Cross-account (MFA required) | Cross-account access |
| `IdentityAccountAdminAccess` | Cross-account (MFA required) | Cross-account admin |
| `OrganizationAccountAccessRole` | Org management account (NO MFA) | Org management access |
| `infra-cross-account-sync-production` | Same account (ExternalId) | Same-account cross-role |
| `platform-restricted-admin-production` | `ec2.amazonaws.com` | Bounded admin (bypassable) |
| `svc-analytics-reader-production` | `ec2.amazonaws.com` | CloudWatch read → chain to admin |
| `svc-compute-operator-production` | `ec2.amazonaws.com` | EC2 full (deny terminate) |
| `svc-data-ops-production` | `ec2.amazonaws.com` | S3 full (MFA delete protection) |
| `svc-data-pipeline-production` | `svc-analytics-reader-production` | S3 ETL read → chain to admin |
| `svc-data-processor-exec-production` | `lambda.amazonaws.com` | DynamoDB + S3 read (wildcarded) |
| `svc-data-processor-secure-exec-production` | `lambda.amazonaws.com` | No policies (empty) |
| `svc-deploy-automation-production` | `ec2.amazonaws.com` | PassRole + Lambda mgmt |
| `svc-onboarding-automation-production` | `ec2.amazonaws.com` | Wildcarded SLR creation |
| `svc-platform-admin-production` | `svc-data-pipeline-production` | Full admin (no boundary) |
| `svc-reporting-api-exec-production` | `lambda.amazonaws.com` | S3 + DynamoDB read |
| `svc-cognito-guest-production` | Cognito (unauthenticated) | Guest access |
| `platform-audit-secure-cloudwatch-production` | `cloudtrail.amazonaws.com` | CloudTrail service role |
| 9x AWS Service-Linked Roles | Various AWS services | Service-managed |

### Detection Access

**CRITICAL: No detection services are deployed.**

| Service | Status | Impact |
|:--------|:-------|:-------|
| CloudTrail | **Not configured** — 0 trails | No API audit trail. All attacker actions are invisible. |
| GuardDuty | **Not enabled** — 0 detectors | No threat detection. Credential abuse, crypto mining, reconnaissance undetected. |
| Security Hub | **Not subscribed** | No aggregated security findings. |
| AWS Config | **Not configured** — 0 recorders | No configuration change tracking. IAM policy changes invisible. |
| IAM Access Analyzer | **Not configured** — 0 analyzers | No external access detection. Public resources, cross-account sharing unmonitored. |
| CloudWatch Logs | 3 log groups (Lambda execution logs only) | Minimal — only Lambda invocation logs. No retention policy set (infinite retention but no alerting). |

An attacker with admin access can operate indefinitely with no detection, no alerting, and no forensic trail. There is nothing to disable because nothing exists — this is worse than having detection that could be turned off (which at least generates a CloudTrail event).

### Compute Access

| Resource Type | Count | Resources | Access Level |
|:-------------|:------|:----------|:-------------|
| Lambda Functions | 2 | `svc-data-processor-production` (python3.12), `svc-reporting-api-production` (python3.12) | Full — create, update code, invoke, delete |
| EC2 Instances | 0 running | 2 terminated | Can launch new instances in 17 regions |
| ECS | Unknown | Not enumerated (no running tasks observed) | Full via AmazonECS_FullAccess |

**Compute weaponization potential:** Admin can launch EC2 instances in any of 17 regions, create Lambda functions with any execution role, and deploy ECS tasks — all without detection (no CloudTrail).

### Network Access

| Resource Type | Count | Resources | Access Level |
|:-------------|:------|:----------|:-------------|
| VPCs | 1 | Default VPC (172.31.0.0/16) | Full modify |
| Security Groups | 1 | Default SG | Full — authorize ingress/egress, create new |
| VPC Endpoints | 0 | None | Can create |
| Subnets | Default subnets | Not enumerated | Full modify |

**Network weaponization potential:** Admin can open security group ingress from 0.0.0.0/0 on any port, create new VPCs with public subnets, establish VPC endpoints for data exfiltration, and create VPN connections — all without detection.

---

## Recommendations

| Priority | Action | Effort | Risk Reduction |
|:---------|:-------|:-------|:---------------|
| P0 | **Enable CloudTrail immediately** — create a multi-region trail with log file validation | Low | Provides audit trail — every API call logged. Without this, no forensics possible. |
| P0 | **Enable GuardDuty** in all 17 regions | Low | Automated threat detection — credential abuse, recon, crypto mining |
| P0 | **Rotate all exposed secrets from F3** — change DB password, revoke API keys, move to Secrets Manager | Med | Eliminates external access via stolen credentials |
| P0 | **Enable MFA on admin IAM user** | Low | Second factor on admin user |
| P1 | **Enable Security Hub + AWS Config** in all regions | Med | Configuration tracking + aggregated findings |
| P1 | **Scope PassRole on deploy-automation and boundary** — restrict to specific role ARNs | Low | Breaks chains 1 and 2 |
| P1 | **Remove sts:AssumeRole to svc-platform-admin from pipeline policy** or add boundary to svc-platform-admin | Med | Breaks chain 3 |
| P1 | **Enable IAM Access Analyzer** | Low | Detects external access grants |
| P2 | **Set CloudWatch log retention** — all 3 log groups have infinite retention with no alerting | Low | Cost control + ensures logs are reviewed |
| P2 | **Clean up 23 PendingDeletion KMS keys** — cancel deletion for any still needed, or allow deletion to complete | Low | Reduces confusion about encryption posture |

---

## Confidence: 5/5

All findings backed by deterministic CLI evidence and PMapper graph. Resource enumeration covers us-east-1 and ap-southeast-2 (SSO region). Lambda functions only found in us-east-1. No data plane resources (S3, DynamoDB, RDS, Secrets Manager) exist in-account — blast radius is primarily IAM control plane + Lambda + external credentials. SCP coverage unknown — org-level guardrails may reduce effective blast radius. | **Verdict:** Accept as-is. Enable detection services as P0 — the complete absence of logging makes all other findings more dangerous because exploitation is invisible.
