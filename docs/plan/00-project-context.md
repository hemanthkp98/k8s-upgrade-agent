# k8s-upgrade-agent — Project Context

> **Read this file first.** Every task prompt in the version files assumes the builder (Antigravity) has read this document in full. When a prompt says "per the project context", it means the rules, layout, and conventions defined here.

---

## 1. What this project is

`k8s-upgrade-agent` (CLI: `kua`) is an open-source, AI-assisted agent that **plans, gates, executes, and verifies Kubernetes version upgrades**. It starts with **Amazon EKS**, then adds **AKS**, **GKE**, and **on-prem (kubeadm / RKE2)** through provider adapters.

It is not a "let the LLM run kubectl" toy. It is a **deterministic upgrade engine with an LLM reasoning layer** and **PR-based human approval gates**:

| Layer | Responsibility | Who decides |
|---|---|---|
| Collectors | Gather facts about the cluster (read-only) | Code |
| Rules engine | Turn facts into blockers / warnings with severities | Code (deterministic) |
| Reasoning layer (Bedrock) | Explain risk, correlate findings, prioritise, write the narrative, judge verification signals | LLM — advisory only |
| Plan-as-code | A YAML upgrade plan pinned to a cluster-state fingerprint | Code + humans |
| Approval gate | Pull request (CODEOWNERS / branch protection) | Humans |
| Executor | Allow-listed, idempotent, resumable actions (Step Functions) | Code, triggered by merge |
| Verification | Compare post-upgrade metrics against a pre-upgrade baseline | Code thresholds + LLM interpretation |
| Audit | Hash-chained, tamper-evident CloudWatch log of every fact, decision and action | Code |

### Why it exists
- Clusters fall behind because upgrades are risky and tedious; EKS clusters that fall behind land in **extended support**, which costs significantly more per cluster-hour.
- Existing tools cover pieces (EKS upgrade insights, pluto/kubent, managed node group rolling updates, Karpenter drift) but nothing **correlates** them into one risk assessment, **gates** the change through a reviewable PR, and **verifies** workloads against a baseline afterwards.
- The durable value is in **readiness reasoning + gating + verification**, not in re-implementing what cloud providers already do for execution.

### Target users
Platform / SRE teams running one to many EKS clusters, who already use Terraform / eksctl / GitOps and want upgrades to be boring.

---

## 2. Upgrade flow (end state, v0.4+)

```
 ┌──────────────┐   ┌─────────────┐   ┌───────────────┐   ┌──────────────┐
 │ 1. SCAN      │──▶│ 2. PLAN +   │──▶│ 3. PR GATE(S) │──▶│ 4. EXECUTE   │
 │ read-only    │   │ risk report │   │ human approve │   │ allow-listed │
 └──────────────┘   └─────────────┘   └───────────────┘   └──────┬───────┘
                                                                 │
   Execution order per minor-version hop:                        ▼
   a) Pre-CP remediation (charts/plugins compatible with BOTH versions) — PR tier 1
   b) Control plane +1 minor (ONE-WAY, no rollback)                  — PR tier 2 (2 approvers)
   c) EKS managed add-ons: vpc-cni, CoreDNS, kube-proxy, EBS CSI
   d) Green node group at target version, tainted                    — PR tier 3
   e) Canary smoke test on green → untaint green → cordon blue
   f) Drain blue in batches (Eviction API, PDB-aware), verify SLOs per batch
   g) Soak period (blue kept cordoned = rollback path)
   h) Remove blue node group                                        — PR tier 4
   i) Final verification + report
```

**Hard facts the whole codebase must respect:**
1. Control plane upgrades are **one minor version at a time** and **cannot be rolled back**.
2. kubelet must **never be newer** than the API server; it may be **up to 3 minors older** (Kubernetes ≥ 1.28 skew policy). Multi-hop plans must track this.
3. Compatibility / deprecated-API checks happen **before** the control plane upgrade, never after.
4. Node-phase rollback = uncordon blue, cordon green, drain green. Control-plane rollback does not exist.

---

## 3. Non-negotiable design principles

1. **The LLM never executes anything.** It receives facts and returns structured JSON. Every mutation is a named, allow-listed action implemented in code (`executor/actions/*`).
2. **The LLM can add or annotate risk, never lower it.** A deterministic blocker stays a blocker regardless of LLM output.
3. **All cluster-derived text is untrusted input.** Pod logs, events, annotations, labels, ConfigMap contents, and image names can contain prompt injection. Wrap them in `<untrusted_cluster_data>` tags, truncate them, and never let them change tool choice or plan content.
4. **Approve exactly what executes.** Every plan carries a `snapshot_fingerprint`. Before executing, recompute it; on material drift → stop and require re-approval. Plans expire.
5. **Read-only by default.** Anything that mutates needs `--execute`, a merged PR, and a valid plan signature.
6. **Idempotent + resumable.** Every executor step checks current state before acting, so it can be retried safely. Execution state lives in DynamoDB with a per-cluster lock.
7. **Least privilege.** Separate IAM roles: `scanner` (read-only), `pr-bot` (GitHub App, no merge rights), `executor` (assumable only from the merge workflow on a protected branch).
8. **Never read Kubernetes Secrets by default.** Derive Helm chart versions from `helm.sh/chart` / `app.kubernetes.io/version` labels. Reading Helm release secrets is an explicit opt-in (`scan.helm_release_secrets: true`).
9. **Everything is auditable.** Every collected fact summary, rule result, LLM request/response (redacted), approval, and action goes to the hash-chained audit log.
10. **Provider-agnostic core.** Nothing in `kua/core`, `kua/rules`, `kua/llm`, `kua/plan`, or `kua/gitops` may import a cloud SDK. Cloud code lives only in `kua/providers/<name>/`.

---

## 4. Tech stack (fixed decisions)

| Concern | Choice |
|---|---|
| Language | Python 3.12 |
| Packaging | `uv` + `pyproject.toml` (hatchling backend) |
| CLI | `typer` + `rich` |
| Models / validation | `pydantic` v2 |
| Kubernetes API | `kubernetes` official Python client |
| AWS | `boto3` / `botocore` |
| LLM | Amazon Bedrock **Converse API** (`bedrock-runtime.converse`) with `toolConfig` for structured output. Model ID configurable; default is a Claude model on Bedrock. |
| Agent hosting (v0.3+) | Amazon Bedrock **AgentCore Runtime** (reasoning service) — verify current SDK (`bedrock-agentcore`) API against AWS docs before coding |
| Orchestration (v0.3+) | AWS Step Functions (Standard workflows) + Lambda (container image) |
| State / locks | DynamoDB |
| Audit | CloudWatch Logs (KMS-encrypted) → S3 export with Object Lock (v1.0) |
| GitHub | GitHub App via `githubkit` (or `PyGithub` if simpler); PRs, checks, comments |
| HCL editing | `python-hcl2` for *reading*; surgical text edits for *writing* (preserve formatting) |
| YAML | `ruamel.yaml` (round-trip, preserves comments) |
| Templates | `jinja2` |
| Tests | `pytest`, `pytest-cov`, `moto` (AWS mocks), `kind` for Kubernetes integration tests, `syrupy` snapshot tests for reports |
| Lint / type | `ruff`, `mypy --strict` on `kua/core`, `kua/rules`, `kua/plan` |
| IaC for the agent itself | Terraform module under `infra/terraform/` |
| CI | GitHub Actions |

---

## 5. Repository layout (target)

```
k8s-upgrade-agent/
├── pyproject.toml
├── README.md
├── LICENSE                         # Apache-2.0
├── SECURITY.md
├── docs/
│   ├── plan/                       # these planning files
│   ├── architecture.md
│   ├── threat-model.md
│   └── providers/eks.md
├── kua/
│   ├── __init__.py
│   ├── cli/                        # typer app: scan, plan, pr, execute, audit
│   ├── config/                     # settings model + loader
│   ├── core/
│   │   ├── models.py               # Finding, Severity, ClusterSnapshot, ...
│   │   ├── versions.py             # semver/minor math, skew rules
│   │   ├── fingerprint.py
│   │   └── errors.py
│   ├── audit/                      # hash-chained audit logger, sinks
│   ├── collectors/                 # provider-agnostic k8s collectors
│   ├── providers/
│   │   ├── base.py                 # Provider protocol
│   │   ├── eks/
│   │   ├── aks/                    # v1.1
│   │   ├── gke/                    # v1.2
│   │   └── onprem/                 # v1.3
│   ├── rules/                      # deterministic risk rules
│   ├── llm/                        # Bedrock client, prompts, schemas, sanitiser
│   ├── report/                     # markdown/json renderers + templates
│   ├── plan/                       # plan schema, generator, validator, signer
│   ├── gitops/                     # GitHub App, IaC adapters, PR composer
│   ├── executor/                   # actions, state store, lock, step handlers
│   └── verify/                     # baseline capture + comparison
├── data/
│   ├── deprecations.yaml           # removed/deprecated APIs by k8s version
│   └── addon-matrix.yaml           # third-party add-on compatibility
├── infra/
│   ├── terraform/                  # deploys scanner/executor/log groups/IAM
│   └── stepfunctions/              # ASL definitions
├── tests/
│   ├── unit/
│   ├── integration/                # kind-based
│   ├── e2e/                        # real EKS sandbox, opt-in
│   └── fixtures/
└── .github/workflows/
```

---

## 6. Core domain model (shared vocabulary)

These names must be used consistently in code, prompts, and docs.

- **`ClusterRef`** — `provider`, `name`, `region`/`location`, `account`/`subscription`/`project`.
- **`ClusterSnapshot`** — everything collected in one scan: control plane version, node groups/pools, compute types, workloads summary, PDBs, add-ons, Helm releases (label-derived), insights, deprecated API usage, capacity, baseline metrics reference. Immutable once built.
- **`Finding`** — `id` (stable, e.g. `DRAIN-PDB-ZERO-DISRUPTION`), `severity` (`BLOCKER` | `HIGH` | `MEDIUM` | `LOW` | `INFO`), `title`, `detail`, `resources` (list of `kind/namespace/name`), `evidence` (dict), `remediation`, `source` (`rule` | `insight` | `llm`), `phase` (`pre-cp` | `cp` | `addons` | `nodes` | `post`).
- **`RiskReport`** — snapshot fingerprint, findings, overall risk (`LOW`/`MEDIUM`/`HIGH`/`BLOCKED`), upgrade path, LLM narrative (clearly labelled), generated_at.
- **`UpgradePlan`** — the YAML contract approved via PR (schema defined in v0.2).
- **`Action`** — an allow-listed executor step with `name`, `params`, `preconditions`, `idempotency_key`.
- **`AuditEvent`** — `run_id`, `seq`, `ts`, `type`, `actor`, `payload`, `prev_hash`, `hash`.

---

## 7. Audit logging contract

- Log group: `/k8s-upgrade-agent/<cluster-name>` (configurable prefix). Stream: `<run_id>`.
- Every event is JSON with `hash = sha256(canonical_json(event_without_hash))` and `prev_hash` of the previous event in the stream (first event: `prev_hash = "GENESIS"`).
- Log groups should be created by the Terraform module (KMS key, retention). The agent may create them only if `audit.create_log_group: true` **and** the IAM role allows it. The agent's role must never have `logs:Delete*`.
- Redaction: strip values of env vars, anything matching secret patterns (AWS keys, tokens, PEM blocks) before logging or sending to the LLM.

---

## 8. Conventions for the builder (Antigravity)

- **One task = one PR-sized change.** Don't implement future tasks early.
- Every task ends with: code, unit tests, docstrings, updated `CHANGELOG.md` entry under `## [Unreleased]`, and a passing `ruff` + `mypy` + `pytest`.
- Public functions have type hints and docstrings with an example where useful.
- No network calls in unit tests. Mock AWS with `moto` or `botocore.stub.Stubber`; mock Kubernetes with fixtures or `kind`.
- Where AWS/Azure/GCP API specifics are uncertain, **check the official SDK docs before coding**, and write a short comment citing which API is used.
- Never hardcode versions of third-party add-ons in code; they live in `data/*.yaml`.
- Logging: `structlog` for operational logs (stderr), `kua.audit` for audit events. Don't mix them.
- Exit codes for CLI: `0` ok, `1` internal error, `2` usage error, `10` scan completed with BLOCKERs, `11` drift detected, `12` gate not satisfied.

---

## 9. Version roadmap

| Version | Theme | File |
|---|---|---|
| v0.1 | Read-only readiness scanner + risk report (EKS) | `01-v0.1-readiness-scanner.md` |
| v0.2 | Plan-as-code, IaC detection, PR approval gate, remediation PRs | `02-v0.2-plan-as-code-and-pr-gate.md` |
| v0.3 | Execution engine on AWS (Step Functions + AgentCore) + node blue/green | `03-v0.3-execution-engine-and-node-bluegreen.md` |
| v0.4 | Control plane + managed add-ons + multi-hop + Karpenter/Fargate/self-managed | `04-v0.4-control-plane-addons-multihop.md` |
| v1.0 | EKS GA: security hardening, fleet scan, evals, packaging, docs | `05-v1.0-eks-ga-hardening-and-release.md` |
| v1.1 | AKS adapter | `06-v1.1-aks-adapter.md` |
| v1.2 | GKE adapter | `07-v1.2-gke-adapter.md` |
| v1.3 | On-prem adapter (kubeadm, RKE2) | `08-v1.3-on-prem-adapter.md` |

Each version is independently useful and publishable. Tag a GitHub release at the end of each.

---

## 10. How to use the prompts

Each task in a version file has:
- **ID and name** (e.g. `V01-T05 — Cluster inventory collector`)
- **Why** — the purpose
- **Depends on** — earlier tasks
- **Antigravity prompt** — paste it as-is. It starts with a standard preamble:

> *Read `docs/plan/00-project-context.md` and follow its principles, stack, layout and conventions. Implement only this task.*

Then it gives exact files, signatures, behaviour, edge cases, tests, and acceptance criteria.

**Before each task:** make sure the previous task's tests pass. **After each task:** review the diff yourself — you are the approval gate for the agent that builds the agent.
