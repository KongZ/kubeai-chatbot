# Skills

Skills are reusable, named instruction sets that guide the AI agent when handling specific tasks — such as debugging a `CrashLoopBackOff`, auditing RBAC permissions, or generating resource manifests. They are defined as plain Markdown files and loaded at startup from a directory.

---

## How Skills Work

  1. At startup, KubeAI loads all `.md` files from `SKILLS_DIR`.
  2. The list of available skills (names and descriptions) is injected into the system prompt so the LLM knows what skills exist.
  3. When a user sends a message, KubeAI checks each skill's **trigger keywords** against the message. If a match is found, that skill's full instructions are prepended to the query before it reaches the LLM.
  4. Even without a trigger match, the LLM can read the skill list in the system prompt and autonomously decide to apply the most relevant skill.

---

## Skill File Format

Each skill is a Markdown file with a YAML frontmatter block:

```markdown
---
name: debug-crashloop
description: Debug a CrashLoopBackOff pod step by step
triggers:
  - crashloop
  - CrashLoopBackOff
---

Diagnose the CrashLoopBackOff by following these steps in order:

1. Get pod events to understand recent failures:
   `kubectl describe pod <name> --context <ctx>`
2. Inspect the last container logs before the crash:
   `kubectl logs <name> --previous --context <ctx>`
3. Check resource limits and requests — look for OOMKilled events.
4. Check the liveness/readiness probe configuration in the pod spec.
5. Summarize the root cause and suggest a concrete fix.
```

### Frontmatter fields

| Field         | Required | Description                                                                                        |
| ------------- | -------- | -------------------------------------------------------------------------------------------------- |
| `name`        | Yes      | Unique identifier for the skill. Files without a `name` are silently skipped.                      |
| `description` | No       | One-line explanation surfaced to the LLM in the system prompt.                                     |
| `triggers`    | No       | List of keywords that auto-activate the skill when found in the user's message (case-insensitive). |

The body (everything after the closing `---`) becomes the skill's instructions, passed verbatim to the LLM when the skill is activated.

---

## Configuration

Set the `SKILLS_DIR` environment variable to the directory containing your skill files:

```yaml
env:
  SKILLS_DIR: "/etc/kubeai/skills"
```

  - If `SKILLS_DIR` is unset or empty, the agent starts normallywith no skills loaded (non-fatal).
  - If the directory exists but contains no `.md` files, no skillsare registered.
  - If a skill file cannot be parsed, KubeAI logs a warning andskips it.

---

## Helm: Mount Skills via ConfigMap

The recommended way to deploy skills in Kubernetes is to store them in a ConfigMap and mount it into the pod.

### 1. Create the ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubeai-skills
  namespace: kubeai
data:
  debug-crashloop.md: |
    ---
    name: debug-crashloop
    description: Debug a CrashLoopBackOff pod step by step
    triggers:
      - crashloop
      - CrashLoopBackOff
    ---

    Diagnose the CrashLoopBackOff:
    1. kubectl describe pod <name> --context <ctx>
    2. kubectl logs <name> --previous --context <ctx>
    3. Check resource limits and liveness probes
    4. Summarize root cause and suggest a fix

  audit-rbac.md: |
    ---
    name: audit-rbac
    description: Audit RBAC permissions for a user or service account
    triggers:
      - forbidden
      - RBAC
      - unauthorized
      - rbac
    ---

    Audit RBAC permissions:
    1. Identify the subject (user, group, or service account) from the error.
    2. List ClusterRoleBindings and RoleBindings for the subject.
    3. Describe the bound roles to see what permissions are granted.
    4. Use `kubectl auth can-i` to verify specific permissions.
    5. Suggest the minimal role needed for the intended operation.
```

### 2. Configure `values.yaml`

```yaml
env:
  SKILLS_DIR: "/etc/kubeai/skills"

volumes:
  - name: skills
    configMap:
      name: kubeai-skills

volumeMounts:
  - name: skills
    mountPath: /etc/kubeai/skills
    readOnly: true
```

---

## Writing Effective Skills

  - **Be specific about steps.** Number the steps so the LLM follows them in order.
  - **Include kubectl command templates.** The LLM will substitute real resource names and contexts.
  - **Use targeted trigger keywords.** Prefer error messages, status strings, or Kubernetes terms that appear verbatim in user messages (e.g., `CrashLoopBackOff`, `OOMKilled`, `Evicted`).
  - **Keep instructions focused.** A skill should cover one well-defined scenario. Multiple narrow skills work better than one broad skill.

---

## Troubleshooting

**Skills not loading:**

  - Check startup logs for `"Loaded N skill(s) from <dir>"`. If absent, verify `SKILLS_DIR` is set and the directory is mounted correctly.
  - Confirm each skill file has a `name` field in its frontmatter — files without a name are silently skipped.

**Skill not triggering automatically:**

  - Verify the trigger keyword appears in `triggers` and that it matches the exact wording users typically use (case-insensitive matching is applied).
  - The LLM may still apply the skill without a trigger match if it determines the skill is relevant from the system prompt description.

**Skill instructions ignored:**

  - Make sure the body of the file (after `---`) contains clear, actionable instructions.
  - Avoid contradicting the agent's base system prompt — skills extend, not override, the agent's behaviour.
