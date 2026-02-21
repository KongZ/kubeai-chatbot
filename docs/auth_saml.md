# SAML 2.0 Authentication Setup

KubeAI Chatbot supports SAML 2.0 for user authentication, commonly used with enterprise Identity Providers (IdPs) like AWS SSO, Okta, and Azure AD.

## Configuration

To enable SAML, set the following environment variables:

| Variable                | Description                                 | Example                                  |
| :---------------------- | :------------------------------------------ | :--------------------------------------- |
| `AUTH_METHOD`           | Set to `SAML`                               | `SAML`                                   |
| `SAML_IDP_METADATA_URL` | URL to your IdP metadata XML                | `https://idp.example.com/metadata`       |
| `SAML_ENTITY_ID`        | The Entity ID of your chatbot (SP)          | `https://your-chatbot.com/saml/metadata` |
| `SAML_ROOT_URL`         | The base URL of your chatbot                | `https://your-chatbot.com`               |
| `SAML_KEY_FILE`         | Path to the SP private key                  | `/etc/saml/key.pem`                      |
| `SAML_CERT_FILE`        | Path to the SP public certificate           | `/etc/saml/cert.pem`                     |
| `SAML_ROLE_MAPPINGS`    | Map of SAML attributes to K8s cluster roles | `admin:cluster-admin,dev:edit`           |

> [!NOTE]
> **First Value Matching**: For SAML, if an attribute contains multiple values, the chatbot will use the **first value** provided by the IdP for mapping purposes.

## Setup Steps

1. **Generate Certificates**: Generate a private key and public certificate for the chatbot (Service Provider).
  ```bash
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=kubeai-chatbot"
  ```
2. **Configure IdP**:

  * **Single Sign-On URL (ACS)**: `https://<your-domain>/saml/acs`
  * **Audience URI (Entity ID)**: `https://<your-domain>/saml/metadata`
  * **Attribute Statements**: Ensure the IdP sends the user's roles or groups in an attribute (e.g., named `roles`).

3. **Metadata**: Provide the `SAML_IDP_METADATA_URL` so the chatbot can fetch the IdP's public key and endpoints.

## Kubernetes Deployment

Since SAML requires a certificate and private key, you should store them securely in a Kubernetes Secret and mount them into the pod.

### 1. Create a Kubernetes Secret

```bash
kubectl create secret generic kubeai-saml-certs \
  --from-file=key.pem=./key.pem \
  --from-file=cert.pem=./cert.pem \
  -n kubeai
```

### 2. Configure values.yaml

Update your Helm `values.yaml` to configure authentication and mount the secret:

```yaml
authentication:
  method: "SAML"

env:
  - name: AUTH_METHOD
    value: "SAML"
  - name: SAML_IDP_METADATA_URL
    value: "https://idp.example.com/metadata"
  - name: SAML_ENTITY_ID
    value: "https://your-chatbot.com/saml/metadata"
  - name: SAML_ROOT_URL
    value: "https://your-chatbot.com"
  - name: SAML_KEY_FILE
    value: "/etc/saml/key.pem"
  - name: SAML_CERT_FILE
    value: "/etc/saml/cert.pem"
  - name: SAML_ROLE_MAPPINGS
    value: "admin:cluster-admin,developer:edit"

volumes:
  - name: saml-certs
    secret:
      secretName: kubeai-saml-certs

volumeMounts:
  - name: saml-certs
    mountPath: "/etc/saml"
    readOnly: true
```

> [!NOTE]
> The Helm chart automatically adds the necessary `impersonate` permissions to the ClusterRole when `authentication.method` is set to `SAML`.

## Slack Configuration

A sample Slack app manifest for SAML is available at [`docs/slack_app_manifest_saml.yaml`](slack_app_manifest_saml.yaml).

## Kubernetes RBAC

The chatbot uses **Client Impersonation**. Ensure the Service Account running the chatbot has permission to impersonate the roles you map in `SAML_ROLE_MAPPINGS`.

Example ClusterRoleBinding:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubeai-impersonator
subjects:
  - kind: ServiceAccount
    name: kubeai-chatbot
    namespace: kubeai
roleRef:
  kind: ClusterRole
  name: impersonator # A role with "impersonate" verb on "users" and "groups"
  apiGroup: rbac.authorization.k8s.io
```
