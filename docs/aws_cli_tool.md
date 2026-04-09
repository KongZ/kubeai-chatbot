# AWS CLI Tool

The AWS CLI tool allows KubeAI to run `aws` commands against AWS resources on behalf of the user. It follows the same execution model as the kubectl tool — commands are parsed and executed directly without a shell, preventing injection attacks.

---

## What the AWS Tool Can Do

When enabled, the LLM can run `aws` commands to:

  - Describe and list EC2 instances, security groups, VPCs, subnets
  - Query EKS clusters (`aws eks describe-cluster`, `aws eks list-clusters`)
  - Inspect load balancers (ALB/NLB via `aws elbv2`)
  - Check IAM roles and policies (`aws iam get-role`, `aws iam list-attached-role-policies`)
  - Query CloudWatch metrics and log groups
  - List S3 buckets and objects
  - Query RDS instances and snapshots
  - Inspect Route53 hosted zones and records
  - Run `aws sts get-caller-identity` to verify credentials

### Commands that are always blocked

Regardless of `ENABLE_AWS_TOOL`, the following are rejected at the validation layer:

| Blocked command                        | Reason                       |
| -------------------------------------- | ---------------------------- |
| `aws secretsmanager get-secret-value`  | Secret retrieval             |
| `aws ssm get-parameter`                | Secret retrieval             |
| `aws ssm get-parameters`               | Secret retrieval             |
| `aws ssm get-parameters-by-path`       | Secret retrieval             |
| `aws kms decrypt`                      | Credential/secret decryption |
| `aws kms generate-data-key`            | Credential/secret decryption |
| `aws iam create-access-key`            | Credential creation          |
| `aws sts assume-role`                  | Credential escalation        |
| Any compound command (`\|`, `&&`, `;`) | Shell injection prevention   |
| `aws configure` / `aws sso login`      | Interactive mode             |

---

## Enabling the AWS Tool

The tool is **disabled by default**. Set `ENABLE_AWS_TOOL=true` in the pod's environment:

```yaml
# values.yaml
env:
  ENABLE_AWS_TOOL: "true"
```

No other configuration is required when the pod already has IRSA credentials — the tool inherits them from the process environment automatically.

---

## IAM Permissions

The IRSA role attached to the KubeAI service account must have the permissions you want the LLM to use. A minimal read-only policy example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "elasticloadbalancing:Describe*",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "rds:DescribeDBInstances",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to the IRSA role used by the KubeAI service account. Follow the IRSA setup in [cross_cluster_access.md](cross_cluster_access.md) for the full role and trust policy setup.

---

## Cross-Account AWS Access

`aws sts assume-role` is blocked by the tool's validation layer, so cross-account access must be configured at the infrastructure level. There are two approaches depending on how many accounts you need.

---

### Option A — IRSA only (direct OIDC trust, no config file needed)

Account B registers Account A's OIDC provider directly in its own IAM. The pod then assumes Account B's role in a **single** `sts:AssumeRoleWithWebIdentity` call — no `~/.aws/config`, no role chaining. This is the approach described in the [AWS cross-account IRSA guide](https://docs.aws.amazon.com/eks/latest/userguide/cross-account-access.html).

Use this when KubeAI only needs to access Account B resources (the service account annotation points to Account B's role, so all commands run in Account B's context).

#### Step 1: Get Account A's OIDC issuer URL

Run this in **Account A**:

```bash
OIDC_ISSUER=$(aws eks describe-cluster \
  --name cluster-a --region ap-southeast-1 \
  --query "cluster.identity.oidc.issuer" --output text)
# e.g. https://oidc.eks.ap-southeast-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
```

#### Step 2: Register Account A's OIDC provider in Account B

Run this in **Account B**:

```bash
# Get the OIDC thumbprint
THUMBPRINT=$(openssl s_client -connect oidc.eks.ap-southeast-1.amazonaws.com:443 \
  -servername oidc.eks.ap-southeast-1.amazonaws.com 2>/dev/null \
  | openssl x509 -fingerprint -noout \
  | sed 's/SHA1 Fingerprint=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')

aws iam create-open-id-connect-provider \
  --url $OIDC_ISSUER \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list $THUMBPRINT
# Output: arn:aws:iam::ACCOUNT_B_ID:oidc-provider/oidc.eks.ap-southeast-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
```

#### Step 3: Create a role in Account B that trusts Account A's OIDC provider

Run this in **Account B**, using the OIDC issuer path (without `https://`):

```bash
OIDC_PROVIDER="oidc.eks.ap-southeast-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"

cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_B_ID:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:kubeai-chatbot:kubeai-chatbot",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name kubeai-chatbot-cross-account \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy \
  --role-name kubeai-chatbot-cross-account \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

#### Step 4: Annotate the KubeAI service account with the Account B role

```yaml
# values.yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::ACCOUNT_B_ID:role/kubeai-chatbot-cross-account"
```

All `aws` commands now run as the Account B role. No `~/.aws/config` needed.

---

### Option B — IRSA + aws config profiles (multiple accounts)

Use this when KubeAI needs access to **both** Account A and Account B. The IRSA role stays in Account A (default credentials). A named profile in `~/.aws/config` tells the AWS CLI how to assume the Account B role on demand — the SDK handles the `sts:AssumeRole` call transparently when `--profile account-b` is used.

#### Step 1: Create a cross-account role in Account B

```bash
cat > cross-account-trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_A_ID:role/kubeai-chatbot"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name KubeAICrossAccountRole \
  --assume-role-policy-document file://cross-account-trust.json

aws iam attach-role-policy \
  --role-name KubeAICrossAccountRole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

#### Step 2: Allow the Account A IRSA role to assume the Account B role

Add `sts:AssumeRole` to the IRSA role policy in Account A:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::ACCOUNT_B_ID:role/KubeAICrossAccountRole"
}
```

#### Step 3: Mount `~/.aws/config` via ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-config
  namespace: kubeai-chatbot
data:
  config: |
    [default]
    region = ap-southeast-1

    [profile account-b]
    role_arn = arn:aws:iam::ACCOUNT_B_ID:role/KubeAICrossAccountRole
    credential_source = EcsContainer
```

```yaml
# values.yaml
volumes:
  - name: aws-config
    configMap:
      name: aws-config

volumeMounts:
  - name: aws-config
    mountPath: /home/kubeai/.aws
    readOnly: true
```

> `credential_source = EcsContainer` works on EKS because IRSA is compatible with the ECS container credential provider. Alternatively use `credential_source = Environment`.

Users instruct KubeAI to use Account B by specifying the profile in their message:

```
Show me all EC2 instances in Account B using profile account-b
```

The LLM appends `--profile account-b` to commands, e.g.:

```bash
aws ec2 describe-instances --region ap-southeast-1 --profile account-b
```

---

## Verify the Setup

Exec into the KubeAI pod and confirm the AWS CLI works:

```bash
kubectl exec -it deployment/kubeai-chatbot -n kubeai-chatbot -- /bin/bash

# Confirm IRSA credentials are active
aws sts get-caller-identity

# Test a read query
aws eks list-clusters --region ap-southeast-1

# Test cross-account (if configured)
aws sts get-caller-identity --profile account-b
```

---

## Troubleshooting

**`ENABLE_AWS_TOOL` is set but the LLM does not use AWS commands**

  - Confirm the env var value is exactly `"true"` (string, not boolean).
  - Restart the pod after changing env vars.

**`NoCredentialProviders` error**

  - IRSA is not active. Check the service account annotation: `eks.amazonaws.com/role-arn`.
  - Verify the IRSA token is mounted: `ls /var/run/secrets/eks.amazonaws.com/serviceaccount/`.

**`AccessDenied` on a specific command**

  - The IRSA role policy does not include the required action. Add it to the IAM policy attached to the IRSA role.

**`aws sts assume-role` rejected**

  - This command is intentionally blocked by the tool's validation layer. Use Option A (IRSA pointing directly at Account B) or Option B (named profiles via `~/.aws/config`) instead — see [Cross-Account AWS Access](#cross-account-aws-access).

**Cross-account `AccessDenied`**

  - **Option A**: Verify Account A's OIDC provider is registered in Account B IAM (`aws iam list-open-id-connect-providers` in Account B). Verify the Account B role's trust policy references `arn:aws:iam::ACCOUNT_B_ID:oidc-provider/...` (not Account A's ARN) with the correct `sub` condition (`system:serviceaccount:<namespace>:<service-account>`).
  - **Option B**: Verify the Account B role's trust policy allows `arn:aws:iam::ACCOUNT_A_ID:role/kubeai-chatbot` to assume it, and that the Account A IRSA role has `sts:AssumeRole` permission targeting the Account B role ARN.
