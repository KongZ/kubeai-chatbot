# OIDC Authentication Setup

KubeAI Chatbot supports OpenID Connect (OIDC) for user authentication. This is compatible with providers like AWS SSO (IAM Identity Center), Google, Okta, and GitHub (via proxies).

## Configuration

To enable OIDC, set the following environment variables:

| Variable             | Description                                   | Example                                  |
| :------------------- | :-------------------------------------------- | :--------------------------------------- |
| `AUTH_METHOD`        | Set to `OIDC`                                 | `OIDC`                                   |
| `OIDC_ISSUER_URL`    | The URL of the OIDC provider                  | `https://auth.example.com`               |
| `OIDC_CLIENT_ID`     | OAuth2 Client ID                              | `kubeai-chatbot-id`                      |
| `OIDC_CLIENT_SECRET` | OAuth2 Client Secret                          | `your-secret`                            |
| `OIDC_REDIRECT_URL`  | The callback URL registered in your IdP       | `https://your-chatbot.com/auth/callback` |
| `OIDC_ROLE_FIELD`    | JWT claim to map to K8s role (string or list) | `groups`                                 |
| `OIDC_ROLE_MAPPINGS` | Map of IdP roles to K8s cluster roles         | `admin:cluster-admin,dev:edit`           |

## Setup with AWS SSO (IAM Identity Center)

1. In AWS IAM Identity Center, create a new **Custom SAML 2.0 application** (Recommended for SAML) or use an OIDC provider proxy if OIDC is strictly required. 
2. **Redirect URL**: Ensure the Redirect URL in your Slack App and IdP is set to `https://<your-domain>/auth/callback`.
3. **Scopes**: KubeAI requests `openid`, `profile`, and `email` scopes.
4. **Role Mapping**: Configure the `OIDC_ROLE_FIELD` to point to the claim containing your groups or roles.

### Group Mapping Example (AWS SSO)

If your AWS SSO setup provides a `groups` claim with AWS Group names, you can map them as follows in your `values.yaml`:

```yaml
authentication:
  method: "OIDC"
  oidc:
    issuerUrl: "https://portal.sso.us-east-1.amazonaws.com/saml/assertion/..."
    clientId: "..."
    clientSecret: "..."
    roleField: "groups" # The claim name in the JWT
    roleMappings: "AWS-Admins:cluster-admin,AWS-Developers:edit"
```

In this example:

- Users in the **AWS-Admins** group will be impersonated as `cluster-admin`.
- Users in the **AWS-Developers** group will be impersonated as `edit`.

> [!NOTE]
> The Helm chart automatically adds the necessary `impersonate` permissions to the ClusterRole when `authentication.method` is set to `OIDC`.

> [!IMPORTANT]
> **Priority Matching**: If a user belongs to multiple groups that are present in the mapping, the chatbot will use the **first** match it encounters in the user's groups list.

## Slack Configuration

In your Slack App settings under **OAuth & Permissions**:

1. Add `https://<your-domain>/auth/callback` to the **Redirect URLs**.
2. Ensure your app manifest includes the `openid`, `email`, and `profile` scopes.

A sample Slack app manifest for OIDC is available at [`docs/slack_app_manifest_oidc.yaml`](slack_app_manifest_oidc.yaml).

## Kubernetes RBAC

The chatbot uses **Client Impersonation**. Ensure the Service Account running the chatbot has permission to impersonate the roles you map in `OIDC_ROLE_MAPPINGS`.

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
