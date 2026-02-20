# Cross-Cluster Access Setup Guide

This guide explains how to configure KubeAI Chatbot to access multiple Kubernetes clusters across different AWS accounts using IRSA (IAM Roles for Service Accounts) and kubeconfig.

## Architecture Overview

  - **Cluster-A**: Where KubeAI Chatbot is deployed (AWS Account A)
  - **Cluster-B**: Target cluster to access (AWS Account B - different AWS account)

## Prerequisites

  - AWS CLI installed and configured
  - kubectl installed
  - Helm 3.x installed
  - Access to both AWS accounts
  - Cluster-A and Cluster-B already created

---

## Step 1: Setup IRSA with eks:DescribeCluster Permission on Cluster-A

### 1.1 Create IAM Policy for Cross-Account Access

Create an IAM policy in **Account A** that allows describing EKS clusters in **Account B**:

```bash
# Create policy document
cat > eks-cross-account-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": [
        "arn:aws:eks:*:ACCOUNT_B_ID:cluster/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": [
        "arn:aws:iam::ACCOUNT_B_ID:role/EKSCrossAccountRole"
      ]
    }
  ]
}
EOF

# Create the policy
aws iam create-policy \
  --policy-name KubeAICrossAccountEKSAccess \
  --policy-document file://eks-cross-account-policy.json \
  --region ap-southeast-1
```

Replace `ACCOUNT_B_ID` with your Account B's AWS account ID.

### 1.2 Create IAM Role for Service Account (IRSA)

```bash
# Set variables
CLUSTER_A_NAME="cluster-a"
ACCOUNT_A_ID="111111111111"
REGION="ap-southeast-1"
NAMESPACE="kubeai-chatbot"
SERVICE_ACCOUNT="kubeai-chatbot"

# Get OIDC provider for Cluster-A
OIDC_PROVIDER=$(aws eks describe-cluster \
  --name $CLUSTER_A_NAME \
  --region $REGION \
  --query "cluster.identity.oidc.issuer" \
  --output text | sed -e "s/^https:\/\///")

# Create trust policy
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_A_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

# Create IAM role
aws iam create-role \
  --role-name kubeai-chatbot \
  --assume-role-policy-document file://trust-policy.json \
  --region $REGION

# Attach the policy to the role
aws iam attach-role-policy \
  --role-name kubeai-chatbot \
  --policy-arn arn:aws:iam::${ACCOUNT_A_ID}:policy/KubeAICrossAccountEKSAccess
```

---

## Step 2: Annotate KubeAI Service Account with IAM Role

Update your Helm values file to annotate the service account:

```yaml
# values.yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::111111111111:role/kubeai-chatbot"
  name: "kubeai-chatbot"
```

Or apply directly:

```bash
kubectl annotate serviceaccount kubeai-chatbot \
  -n kubeai-chatbot \
  eks.amazonaws.com/role-arn=arn:aws:iam::111111111111:role/kubeai-chatbot
```

---

## Step 3: Create Kubeconfig

### Option A: Manual Kubeconfig Creation

Create a kubeconfig file with multiple cluster contexts.

```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: <BASE64_ENCODED_CA>
    server: https://<CLUSTER_B_API_ENDPOINT>
  name: arn:aws:eks:ap-southeast-1:222222222222:cluster/cluster-b

contexts:
- context:
    cluster: arn:aws:eks:ap-southeast-1:222222222222:cluster/cluster-b
    user: arn:aws:eks:ap-southeast-1:222222222222:cluster/cluster-b
  name: cluster-b

current-context: cluster-b

users:
- name: arn:aws:eks:ap-southeast-1:222222222222:cluster/cluster-b
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args:
      - --region
      - ap-southeast-1
      - eks
      - get-token
      - --cluster-name
      - cluster-b
      - --output
      - json
      env:
      - name: AWS_ROLE_ARN
        value: arn:aws:iam::222222222222:role/EKSCrossAccountRole
      - name: AWS_WEB_IDENTITY_TOKEN_FILE
        value: /var/run/secrets/eks.amazonaws.com/serviceaccount/token
```

### Option B: Generate Kubeconfig Using AWS CLI

```bash
# Generate kubeconfig for Cluster-B (remote cluster)
aws eks update-kubeconfig \
  --name cluster-b \
  --region ap-southeast-1 \
  --role-arn arn:aws:iam::222222222222:role/EKSCrossAccountRole \
  --kubeconfig ./kubeconfig

# Verify contexts
kubectl config get-contexts --kubeconfig ./kubeconfig
```

### Create Kubernetes Secret

```bash
# Create secret from kubeconfig file
kubectl create secret generic kubeconfig \
  --from-file=config=./kubeconfig \
  -n kubeai-chatbot
```

---

## Step 4: Configure Volume Mount

Update your Helm values to mount the kubeconfig secret. See example in `demo/values.yaml`:

```yaml
# local-values.yaml
volumes:
  - name: kubeconfig
    secret:
      secretName: kubeconfig
      optional: false

volumeMounts:
  - name: kubeconfig
    mountPath: "/home/kubeai/.kube"
    readOnly: true
```

Apply the configuration:

```bash
helm upgrade --install kubeai-chatbot ./charts/kubeai-chatbot \
  -n kubeai-chatbot \
  -f demo/values.yaml
```

---

## Step 5: Update aws-auth ConfigMap on Cluster-B

You need to grant Cluster-A's IAM role access to Cluster-B.

### Option A: Manual Update of aws-auth ConfigMap

1. Edit the aws-auth ConfigMap on Cluster-B:

```bash
kubectl edit configmap aws-auth -n kube-system --context cluster-b
```

2. Add the IAM role mapping (see example in `demo/aws-auth.yaml`):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    # ... existing roles ...
    - rolearn: arn:aws:iam::111111111111:role/kubeai-chatbot
      username: kubeai-chatbot
      groups:
        - system:read-only
```

### Option B: Using AWS EKS CLI (Recommended)

```bash
# Create IAM identity mapping
aws eks create-access-entry \
  --cluster-name cluster-b \
  --region ap-southeast-1 \
  --principal-arn arn:aws:iam::111111111111:role/kubeai-chatbot \
  --type STANDARD \
  --username kubeai-chatbot-cross-cluster

# Associate access policy (read-only example)
aws eks associate-access-policy \
  --cluster-name cluster-b \
  --region ap-southeast-1 \
  --principal-arn arn:aws:iam::111111111111:role/kubeai-chatbot \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy \
  --access-scope type=cluster
```

---

## Step 6: Add Cluster-A Outgoing IP to Cluster-B Security Group

Get Cluster-A's NAT Gateway public IPs and add them to Cluster-B's EKS API security group.

### 6.1 Find Cluster-A NAT Gateway IPs

```bash
# Get NAT Gateway IPs for Cluster-A's VPC
VPC_ID=$(aws eks describe-cluster \
  --name cluster-a \
  --region ap-southeast-1 \
  --query 'cluster.resourcesVpcConfig.vpcId' \
  --output text)

aws ec2 describe-nat-gateways \
  --filter "Name=vpc-id,Values=$VPC_ID" \
  --query 'NatGateways[*].NatGatewayAddresses[*].PublicIp' \
  --output text
```

Example output:

```sh
18.0.35.117
18.0.37.11
18.0.38.139
```

### 6.2 Add IPs to Cluster-B Security Group

```bash
# Get Cluster-B's security group
CLUSTER_B_SG=$(aws eks describe-cluster \
  --name cluster-b \
  --region ap-southeast-1 \
  --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' \
  --output text)

# Add ingress rules for each NAT IP
aws ec2 authorize-security-group-ingress \
  --group-id $CLUSTER_B_SG \
  --protocol tcp \
  --port 443 \
  --cidr 18.0.35.117/32 \
  --region ap-southeast-1

aws ec2 authorize-security-group-ingress \
  --group-id $CLUSTER_B_SG \
  --protocol tcp \
  --port 443 \
  --cidr 18.0.37.11/32 \
  --region ap-southeast-1

aws ec2 authorize-security-group-ingress \
  --group-id $CLUSTER_B_SG \
  --protocol tcp \
  --port 443 \
  --cidr 18.0.38.139/32 \
  --region ap-southeast-1
```

---

## Step 7: Instruct AI to Use Specific Cluster Context

When users want to query a specific cluster, they should specify the context or cluster name in their message.

### User Query Examples

**Query Cluster-A (default):**

```sh
Show me all pods in the default namespace
```

**Query Cluster-B (specify context):**

```sh
Show me all pods in cluster-b cluster
```

or

```sh
Use context cluster-b and show me all deployments
```

or

```sh
Switch to cluster-b and list all namespaces
```

### AI Behavior

The AI will:

1. Detect cluster/context mentions in the user's query
2. Use `kubectl --context <context-name>` or `kubectl --kubeconfig /home/kubeai/.kube/config --context <context-name>` for the specified cluster
3. Default to the current context if no cluster is specified

### Verify Configuration

Test the setup by running:

```bash
# Exec into the pod
kubectl exec -it deployment/kubeai-chatbot -n kubeai-chatbot -- /bin/bash

# Test access to Cluster-A (local)
kubectl get nodes

# Test access to Cluster-B (remote)
kubectl get nodes --context cluster-b

# List available contexts
kubectl config get-contexts
```

---

## Troubleshooting

### Issue: "error: You must be logged in to the server (Unauthorized)"

**Solution**: Check that:

  1. IAM role is correctly annotated on the service account
  2. aws-auth ConfigMap on Cluster-B includes the IAM role
  3. IRSA is properly configured with the correct OIDC provider

### Issue: "Unable to connect to the server: dial tcp: lookup ... I/O timeout"

**Solution**: Check that:

  1. Cluster-A's NAT Gateway IPs are added to Cluster-B's security group
  2. Security group allows inbound traffic on port 443
  3. Network connectivity between clusters is working

### Issue: "error: exec plugin: invalid apiVersion"

**Solution**: Update the kubeconfig to use `client.authentication.k8s.io/v1beta1` or `v1` depending on your kubectl version.

### Debug Commands

```bash
# Check service account annotations
kubectl get sa kubeai-chatbot -n kubeai-chatbot -o yaml

# Check if IRSA token is mounted
kubectl exec -it deployment/kubeai-chatbot -n kubeai-chatbot -- ls -la /var/run/secrets/eks.amazonaws.com/serviceaccount/

# Check AWS credentials
kubectl exec -it deployment/kubeai-chatbot -n kubeai-chatbot -- aws sts get-caller-identity

# Test EKS describe-cluster permission
kubectl exec -it deployment/kubeai-chatbot -n kubeai-chatbot -- aws eks describe-cluster --name cluster-b --region ap-southeast-1
```

---

## Security Best Practices

  1. **Use least privilege**: Grant only the minimum required permissions
  2. **Rotate credentials**: Regularly rotate IAM roles and service account tokens
  3. **Audit access**: Enable CloudTrail and EKS audit logs
  4. **Network security**: Use security groups and network policies to restrict access
  5. **Secret management**: Use AWS Secrets Manager or external secrets operator for sensitive data

---

## References

  - [EKS IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latestuserguide/iam-roles-for-service-accounts.html)
  - [EKS Cross-Account Access](https://docs.aws.amazon.com/eks/latest/userguidecross-account-access.html)
  - [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authzrbac/)
  - [AWS EKS Access Entries](https://docs.aws.amazon.com/eks/latest/userguideaccess-entries.html)
