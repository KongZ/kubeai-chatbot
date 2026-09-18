---
name: multi-cluster-summary
description: Answer questions that span multiple Kubernetes clusters (e.g. "check all clusters") using the multi_cluster_query tool instead of looping single-cluster turns
triggers:
  - all clusters
  - every cluster
  - across clusters
  - across all clusters
  - each cluster
  - all the clusters
  - clusters you have access to
  - summarise clusters
  - summarize clusters
  - compare clusters
---

This request spans more than one Kubernetes cluster. Do **not** attempt it yourself by running kubectl with different `--context` values in sequence — that is blocked (one cluster per response, enforced in code) and will exhaust your iteration budget long before you get through every cluster.

Instead, call the `multi_cluster_query` tool **exactly once**:

  - `task`: a precise, self-contained description of what to check, written as if instructing a colleague who will only ever see one cluster. Include exactly what "the answer" looks like (a version string, a yes/no, a count, etc.) so every cluster's sub-investigation returns something directly comparable.
  - `clusters`: the specific context names the user named, if any. Omit this entirely to target every cluster you have access to.

The tool runs one small, read-only, isolated investigation per cluster in parallel (bounded, so it stays fast and cheap regardless of how many clusters exist) and returns a `results` list of `{cluster, result, error}`. Wait for that result — do not try to run any further kubectl commands yourself to double check it.

### Worked example

User: "We're on Istio 1.29 right now, right? Can you check all the clusters you have access to and summarise in a table please."

1. Call `multi_cluster_query` with `task`: "Determine the Istio control plane (istiod) version currently running and report it as a version string (e.g. '1.29.2'). If Istio isn't installed on this cluster, say so instead of guessing." — omit `clusters` to check every reachable cluster.
2. Once the tool returns, format the answer as a Markdown table:

   | Cluster | Result |
   | --- | --- |
   | prod-a | 1.29.2 |
   | prod-b | 1.28.4 (not 1.29) |
   | staging-1 | Istio not installed |

3. If any cluster's `error` field is set, show it in the `Result` column too (e.g. "unreachable: timeout") rather than dropping that row — a partial answer that's honest about a gap is better than a table that silently omits a cluster.
4. Briefly call out anything a human should notice — e.g. which clusters are *not* on the expected version — instead of just dumping the table with no comment.
