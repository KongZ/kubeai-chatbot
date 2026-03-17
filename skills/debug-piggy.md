---
name: debug-piggy
description: Diagnose and troubleshoot issues with Piggy secrets injection (piggysec.com)
triggers:
  - piggy
  - piggysec
  - piggy-env
  - piggy-webhooks
  - install-piggy-env
  - PIGGY_ALLOWED_SA
  - secrets injection
  - secret manager
---

Piggy is a Kubernetes mutating admission webhook that injects AWS Secrets Manager secrets into pod environments via a `piggy-env` init container. Follow this step-by-step diagnostic process.

## How Piggy Works (Context)

When a pod is created:

  1. The Kubernetes control plane triggers Piggy Webhooks via MutatingAdmissionWebhook.
  2. Piggy Webhooks injects an `install-piggy-env` init container into the pod.
  3. At runtime, `piggy-env` starts and contacts Piggy Webhooks over TLS, sending the pod's service account token, pod name, and a command signature (SHA256).
  4. Piggy Webhooks validates credentials via the Kubernetes Token Review API, exchanges the service account token for temporary AWS credentials via STS, then fetches secrets from AWS Secrets Manager.
  5. `piggy-env` receives the secrets and replaces any environment variable prefixed with `piggy:` with the real value.

## Diagnostic Steps

### Step 1: Check the init container status

```sh
kubectl describe pod <pod-name> -n <namespace> --context <ctx>
```

Look for the `install-piggy-env` init container in `Init Containers:`:

  - `Exit Code: 0` — init container succeeded; continue to Step 2.
  - Non-zero `Exit Code` or `State: Waiting` — init container failed; see Troubleshooting below.
  - No `install-piggy-env` container at all — pod was never mutated; see "Pod Not Mutated" below.

Also check that your application container's `Command` starts with `/piggy/piggy-env`:

```yaml
Containers:
  <your-container>:
    Command: /piggy/piggy-env
    ...
    Exit Code: 0   ← success
```

### Step 2: Check Piggy Webhooks logs

Piggy Webhooks may run as multiple replicas. Use `--all-pods` (or `-l`) to collect logs from every pod:

```sh
kubectl logs -l app.kubernetes.io/name=piggy-webhooks -n piggy-webhooks --all-pods --context <ctx>
```

Or list pods first and check each one:

```sh
kubectl get pods -n piggy-webhooks --context <ctx>
kubectl logs <piggy-webhooks-pod-1> -n piggy-webhooks --context <ctx>
kubectl logs <piggy-webhooks-pod-2> -n piggy-webhooks --context <ctx>
```

Look for two expected JSON log lines for your pod:

**Mutation log** (pod was processed by the webhook):

```json
{"level":"info","namespace":"<ns>","owner":"<replicaset>","message":"Pod of ReplicaSet '<name>' has been mutated (took ...)"}
```

**Secret retrieval log** (runtime secret fetch succeeded):

```json
{"level":"info","namespace":"<ns>","pod_name":"<pod>","service_account":"<ns>:<sa>","secret_name":"<ns>/<sa>","message":"Request from [sa=<ns>:<sa>], [pod=<pod>] was successful"}
```

If neither line appears for your pod, see "Pod Not Mutated" below.
If the mutation line appears but the secret line does not (or shows an error), see "Secret Request Failing" below.

### Step 3: Check the application's own logs

```sh
kubectl logs <pod-name> -n <namespace> --context <ctx>
```

Expected success message from `piggy-env`:

```json
{"level":"info","message":"Request secrets was successful"}
```

If this message is absent or shows an error, see Troubleshooting below.

### Step 4: Check Piggy Webhooks pod health

```sh
kubectl get pods -n piggy-webhooks --context <ctx>
```

### Step 5: Enable debug mode (if needed)

For `piggy-env` on a specific pod, add the annotation to the pod spec:

```yaml
annotations:
  piggysec.com/debug: "true"
```

For Piggy Webhooks global debug, set in Helm `values.yaml` and upgrade:

```yaml
debug: true
```

Or set env var `PIGGY_DEBUG=true` in the Piggy Webhooks deployment.

---

## Troubleshooting Reference

### Pod Not Mutated (no `install-piggy-env` init container)

**Cause:** The pod annotation `piggysec.com/piggy-address` is missing or incorrect.

**Fix:** Ensure the `piggysec.com/piggy-address` annotation is set in your HelmRelease. The AWS annotations are optional — `aws-secret-name` defaults to `<namespace>/<pod-service-account>` and `aws-region` is inherited from the Piggy Webhooks deployment setting:

```yaml
podAnnotations:
  piggysec.com/piggy-address: "https://piggy-webhooks.piggy-webhooks.svc.cluster.local"
  # piggysec.com/aws-secret-name: "<namespace>/<secret-name>"  # optional, defaults to <namespace>/<service-account>
```

If the annotation is already present but the pod is still not mutated, try restarting the deployment:

```sh
kubectl rollout restart deployment/<your-deployment> -n <namespace> --context <ctx>
```

Also verify the webhook is configured for your namespace:

```sh
kubectl get mutatingwebhookconfigurations --context <ctx>
```

### Init container fails (non-zero Exit Code)

```sh
kubectl logs <pod-name> -n <namespace> -c install-piggy-env --context <ctx>
```

### Secret Request Failing

**"decision not allowed"** — Service account is not in `PIGGY_ALLOWED_SA`.

Check the `PIGGY_ALLOWED_SA` value in AWS Secrets Manager for the secret. The format is:

```sh
PIGGY_ALLOWED_SA=<namespace>:<service_account_name>
```

For multiple service accounts, use comma separation: `ns1:sa1,ns2:sa2`.

**"unable to communicate with piggy-webhooks"** — Piggy Webhooks is unreachable.

  - Check Piggy Webhooks pods are running: `kubectl get pods -n piggy-webhooks --context <ctx>`
  - If using Istio/Envoy, add a ServiceEntry for Piggy Webhooks in your HelmRelease:

  ```yaml
  servicesEntries:
    - name: piggy-webhooks
      hosts:
        - piggy-webhooks.piggy-webhooks.svc.cluster.local
      location: MESH_INTERNAL
      portName: piggy
      resolution: NONE
  ```

  - For Istio proxy startup timing, add an initial delay annotation:

  ```yaml
  piggysec.com/piggy-initial-delay: "2s"
  ```

**Secret not found / wrong region** — Both annotations are optional but override the defaults. Explicitly set them if the defaults are not correct for this pod:

```yaml
piggysec.com/aws-secret-name: "<namespace>/<secret-name>"  # default: <namespace>/<service-account>
piggysec.com/aws-region: "<aws-region>"                    # default: inherited from piggy-webhooks
```

**Wrong service account** — Verify the pod uses the correct service account with IRSA:

```sh
kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.serviceAccountName}' --context <ctx>
kubectl get serviceaccount <sa-name> -n <namespace> -o yaml --context <ctx>
```

### Secrets injected but env vars still show `piggy:...` value

Confirm env var names in your deployment are prefixed with `piggy:`:

```yaml
env:
  - name: MY_SECRET
    value: "piggy:my-key-in-aws-secret"
```

Only variables prefixed exactly with `piggy:` are replaced by `piggy-env`.

---

## Key Annotations Reference

| Annotation                             | Description                                                                                                                                                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `piggysec.com/piggy-address`           | Webhooks service URL (required)                                                                                                                                                                               |
| `piggysec.com/aws-secret-name`         | AWS secret identifier (default: `<namespace>/<service-account>`)                                                                                                                                              |
| `piggysec.com/aws-region`              | AWS region (default: inherited from piggy-webhooks)                                                                                                                                                           |
| `piggysec.com/aws-secret-version`      | Secret version (default: `AWS_CURRENT`)                                                                                                                                                                       |
| `piggysec.com/debug`                   | Enable debug logging in `piggy-env` (`"true"`)                                                                                                                                                                |
| `piggysec.com/piggy-initial-delay`     | Delay before secret fetch (e.g. `"2s"` for Istio)                                                                                                                                                             |
| `piggysec.com/piggy-number-of-retry`   | Retry attempts on failure (default: `0`)                                                                                                                                                                      |
| `piggysec.com/piggy-ignore-no-env`     | Don't fail if no secrets exist (default: `false`)                                                                                                                                                             |
| `piggysec.com/piggy-enforce-integrity` | Validate container command SHA256 (default: `true`). When enabled, manually exec-ing `/piggy/piggy-env` inside a container will be rejected — the signature won't match. Set to `"false"` only for debugging. |
