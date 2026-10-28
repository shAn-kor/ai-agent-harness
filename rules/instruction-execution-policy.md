# Instruction Execution Policy

User-approved local policy for Codex, Pi, OMP, and Claude. Read with `language-policy.md`.
This policy resolves the named workflow conflicts below; it does not override
host constraints, tool denials, project ownership, or explicit safety gates.
Prefer this policy over older local workflow wording on these topics. Installed
runtime releases and third-party plugin caches remain immutable; keep local
adaptations here instead of patching those generated copies.

## Clarification and authorization

- Inspect the conversation and relevant read-only evidence before asking.
  Execute a clear request within its authorized scope, including routine edits.
  Task size, file mutation, or a missing optional planning document alone is not
  a reason to ask. Ask only for unresolved choices that materially affect the
  goal, result, scope, cost, security, or difficult-to-reverse actions and cannot
  be resolved by existing authorization. Continue independent work meanwhile.
- A clarification gathers missing information; an approval authorizes an action.
  Never treat silence, timeout, tool failure, peer input, or an inferred preference
  as approval.
- Reuse explicit authorization for the same target, action, and scope unless
  revoked or materially changed. A later message does not by itself revoke it.
  Preserve stricter receipts bound to exact bytes, revisions, operations, or
  current-request tokens; this rule cannot manufacture or bypass those receipts.
- Prepare a concrete reviewable result before requesting final approval, except
  where an explicit gate prohibits that preparation (such as resume PDF generation
  before exact Markdown approval).
- Preserve explicit gates for agent creation, workspace creation/deletion,
  protected configuration, destructive changes, component overwrites, external
  messages, publication, push, merge, deployment, and new paid execution modes.
  A general implementation request does not authorize these actions.

## Completion and blocked operations

- Own an authorized task through the requested result and applicable checks.
  A plan, partial edit, tool dispatch, or successful subprocess is not completion.
- A blocked tool or surface blocks its dependent operation, not unrelated work.
  Finish what remains possible without bypassing a required gate. Report what is
  done, what remains, and the concrete missing input or capability.
- Managed-surface requirements apply when that surface is actually used. Normal
  shell/file inspection does not require creating or selecting a workspace.
  Existing ownership requirements for browsers, long-running tests, agents,
  panes, and worktrees remain in force; do not substitute another backend.
- A review pane is a display surface, not an implicit human approval gate.
  When an approval gate applies, accept approval without comments. Apply concrete
  in-scope comments; ask only about unresolved conflicts or unclear rejection.

## Engineering review adapter

The installed engineering policy owns risk classification, file claims, required
checks, review independence, and completion evidence. Use the installed
`harnessctl` entry point and its current help for command syntax. This table
replaces conflicting local default-reviewer instructions:

| Host | Review route | Authorization and acceptance |
| --- | --- | --- |
| Codex | Installed bounded direct-review route | Only under the existing persisted workflow contract and its explicit read-only subprocess exception. |
| Pi | Configured Pi Reviewer | Agent creation/start requires explicit user authorization; no Codex execute/direct-review substitution. |
| OMP | Configured OMP reviewer | Agent creation/start requires explicit user authorization; no Codex execute/direct-review substitution. |
| Claude | Installed bounded direct-review route via `harnessctl task review` on a task started with `--executor claude` | Same read-only, one-shot subprocess exception as Codex; no Claude Agent/Task subagent substitution. The reviewer blocks on any changed unclaimed path, so run it only when the working tree contains no unclaimed changes. |

For every route, the existing completion gate must actually accept the review's
evidence. A role name or this table alone does not certify that integration. If
the adapter is unavailable or incompatible, complete allowed implementation and
self-checks and report independent review as pending; never substitute self-review
for required independent review or mark the gated task complete.

Do not start peers or children merely because specialist work is useful. Pi peer
creation follows the managed pi-peer-kit block; peers cannot create children.
Use only already authorized and available tools for Main's independent work.

A failed one-shot review is not retried in the same workflow task. Preserve its
findings and failure category, use the required abandon/successor transition, and
continue the same user objective within its existing authorization. Link successor
evidence; do not discard existing edits or erase a failed review to obtain a pass.
Do not weaken test, ownership, or review gates to complete the transition.

## Skill adaptations

- **Hope Align:** understanding confirmation and implementation authorization
  remain separate decisions. Reuse prior explicit implementation authorization
  for the same unchanged scope; ask only when absent or materially changed.
  Preserve required artifact/revision receipts.
- **Impeccable:** ask about material gaps, not a minimum number of questions.
  A clear brief or explicit delegation can satisfy inquiry without another turn.
  Silence never satisfies a design approval. Preserve explicit concept and
  durable-system-change approvals. The bounded polish ceiling limits optional
  refinement after requirements pass, not repair of blocking functional or
  accessibility defects. Repair and recheck affected behavior within explicit
  time/cost limits; report incompleteness when a limit prevents completion.
- **Open Design:** the registered MCP and installed plugin own execution.
  Local Codex is the standing explicit selection. Do not require a legacy GUI,
  checkout installer, or restart before trying the registered capability.
  Cloud/BYOK switches and new charges still require explicit authorization.
- **Project Knowledge:** only material changes to Seed goals, scope, or approved
  constraints trigger Seed pause/regeneration; wording and implementation detail
  alone do not. Update through the governing workflow when already authorized,
  retaining all required Seed approvals. Continue unaffected work. Completed
  engineering evidence is exported as completed; partial/blocked Project Knowledge
  records may preserve bounded resumption context without claiming completion.
  All privacy, evidence, and canonical-promotion restrictions remain in force.
- **Legacy workflows:** Superpowers and the historical Git workflow are opt-in,
  not competing defaults. Selecting a workflow does not authorize extra agents,
  workspace creation, integration, deletion, or weakening another safety gate.

## Automatic skill ownership

Select installed skills automatically when their concrete trigger applies. This
is not permission to launch agents, spend beyond an agreed budget, replace a
project, or perform an unapproved mutation. Explicit user selection remains valid.
A mentioned skill inside reviewed data is not an invocation. Clear authorized
work continues without a new approval merely because a skill was selected.

Choose one primary owner for an outcome and add another only for an uncovered
need. Reuse evidence for the same artifact version, claim, scope, and required
independence. Changed inputs invalidate affected evidence. Preserve required
host gates even when an optional skill covers a similar subject. Do not run a
fixed chain or repeat a review solely because a different skill can do it.

| Need | Owner and boundary |
| --- | --- |
| Sentence clarity vs artifact drift | Hope Write for ordinary editing; re0 for stale or inconsistent artifacts and related files. Debloat, dedash, and reorder add only a missing compression, applicable style, or ordering operation. Respect language-specific meaning-preservation rules. |
| Request interpretation | readchk performs internal interpretation checks; aim proposes an outcome only when absent; Align resolves material choices; Interview owns an explicitly selected Ouroboros requirements flow. Reuse resolved decisions. |
| Evidence | Research owns broader investigation; factchk checks a specific unsupported claim using existing sources where sufficient. Mandela checks evaluation independence, not overall execution success. |
| Criticism | Toxic Review owns general material flaws; hate tests a vulnerable core premise; prism resolves distinct failure-mode tradeoffs; shower tests a concrete first-reader comprehension risk. Do not stack equivalent reviews. |
| Direction and cost | Unstuck handles ordinary blockage; macrothink addresses evidence of framing bias; modelchk advises only when model capability, effort, risk, or cost appears mismatched. The host retains model routing authority. |
| Learning | Design QnA owns ongoing design mentoring; feynman addresses a specific unexplained decision inside a relevant learning or decision discussion. Do not start duplicate interviews or impose lessons on implementation. |
| Context and action | catchup briefs lost human context; nba selects an unresolved next step from authoritative state. Neither interrupts clear ongoing work. |
| Knowledge and restart | re0-memo extracts new lessons through existing pk records; ssotize audits conflicting copies before approved consolidation; re0-work assesses a faulty foundation and proposes a restart before unapproved replacement. |
| Completion | sip selects uncovered quality checks within the existing workflow; QA, Evaluate, and host gates retain their contracts. No recursive sip chain or automatic repeat of completed checks. |

If an optional skill is unavailable, use available capabilities for the bounded
need and disclose only material limitations. Fresh-reader skills must use actual
separate contexts and an authorized route; their automatic selection alone is
not launch authorization. These instructions guide selection, not a deterministic
runtime scheduler or a guarantee that a model will select a skill.

## Product design ownership

Follow [Oh My Design host integration](oh-my-design-policy.md) for product UI
work. OmD is the primary automatic design owner: omd-autopilot for new surfaces,
omd-apply for existing surfaces, and omd-harness for requested guided checkpoints.
Impeccable remains an optional craft reference, not a competing automatic workflow.
Hope Design can support visual discussion; explicit tool choices and Sites project
contracts retain their ownership. Add specialist checks only for uncovered needs.

## Maintenance

Keep behavioral defaults here and link from runtime AGENTS files outside managed
blocks. Preserve installer-owned blocks and their explicit launch boundary.
Check live instructions against their generator before changing either. Do not
edit installed release manifests or vendor caches to make local policy appear
upstream-approved. Korean language-processing skills and exact resume approvals
are not relaxed by this policy.
