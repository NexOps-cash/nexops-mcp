# Migration Plan — Parallel AI Contract Architect

**Date:** 2026-07-11  
**Status:** Proposed incremental rollout  
**Depends on:** [`parallel_contract_architecture.md`](parallel_contract_architecture.md)  
**Non-goals:** Redesigning the compile loop, compile repair, or audit

## Migration objective

Introduce an editable, reviewable protocol architecture before generation without breaking:

- Existing non-interactive generation
- Supported single-pattern prompts
- Current MCP request and response envelopes
- Existing compile and repair behavior
- Existing audit behavior
- Benchmark reproducibility

The migration should expand the graph-first guided flow already present in NexOps. It should not create a second planning product beside `ConstraintGraph`.

## Current baseline

The repository currently has two paths:

```text
Fast / non-interactive
Prompt → legacy intent and capability routing → generation → compile loop → audit

Guided / interactive
Prompt → graph extraction → confidence and validation → clarification
       → review and confirm → graph/module bridge → generation
       → compile loop → audit
```

The guided path already defaults to graph v2 through `NEXOPS_SPEC_GRAPH_V2`. The non-interactive and benchmark paths remain legacy by default. This is the correct seam for migration.

The principal gaps are protocol-level contract boundaries, covenant state ownership, detailed asset flow, transaction ordering, robust constraint extraction, revisioned reconciliation, and a complete multi-contract generation manifest.

## Compatibility strategy

### Keep the request envelope stable

Retain existing actions:

- `generate`
- `spec_turn`
- `spec_review`
- `spec_confirm`
- `spec_modify`

Add fields under versioned payloads rather than creating incompatible actions. Existing clients may continue reading `specification`, `review`, `planning_report`, and `composition_support`.

### Evolve the graph in place

The canonical artifact should evolve from the existing graph schema to a protocol architecture schema. During migration:

- Continue returning `constraint_graph` for current clients.
- Add `architecture_schema_version`.
- Add new node and edge kinds in a backward-compatible way.
- Project `ContractSpecification`, `ExecutionPlan`, and `UTXOArchitecture` from the canonical graph.
- Reject clients attempting to edit a newer graph revision using a stale base revision.

Avoid maintaining independent `ConstraintGraph` and `ArchitectureGraph` objects. If product naming changes, preserve one underlying schema and one revision history.

### Preserve the fast path

Fast generation remains the default for supported, high-confidence, single-pattern prompts.

The architect is selected when any of these are true:

- The user explicitly chooses guided design.
- Input is a document rather than a short prompt.
- More than one contract boundary is proposed.
- Three or more independent patterns are detected.
- External dependencies, minting, upgrade, governance recovery, or emergency authority are present.
- A security-critical field is low confidence or contradictory.
- Composition support is experimental or unsupported.

Routing must be backend-authored and observable.

### Preserve downstream systems

The generation handoff may change from flat intent fields to a manifest, but:

- The existing generator remains the code-producing subsystem.
- The compile and repair loop receives generated contract units as it does today.
- The audit system remains a downstream consumer.
- Existing compile and audit results are attached to architecture and contract IDs only for traceability.

No P0–P2 milestone requires changing compile-repair or audit logic.

## Rollout controls

Use independent controls for:

- Architecture extraction
- Parallel planners
- Human review gate
- Graph-native generation manifest
- Non-interactive routing
- Long-document ingestion

Do not use one global flag for the entire program. Independent controls allow shadow evaluation and targeted rollback.

Recommended rollout modes:

1. `legacy`: current behavior only.
2. `shadow`: build an architecture but do not affect responses or generation.
3. `review_only`: expose architecture and allow saving, but generate through the legacy compatibility projection.
4. `manifest_guided`: approved guided sessions generate through the manifest.
5. `routed`: backend automatically chooses fast or architect flow.

Benchmark runs remain pinned to an explicit mode and schema version.

## P0 — Foundation and evidence

### Goal

Prove that NexOps can extract and review a faithful protocol architecture without changing generation behavior.

### Scope

#### Canonical schema

- Extend the existing graph with first-class `Contract`, covenant `State`, and `Transaction` concepts.
- Add detailed asset-flow and state-transition edges.
- Add source document and source-span provenance.
- Add assumptions, alternatives, conflicts, and decisions.
- Add architecture revision, parent revision, schema version, and content hash.
- Preserve lifecycle state as distinct from on-chain state.

#### Source ingestion

- Normalize prompts, READMEs, bounties, and whitepaper sections into a `SourceBundle`.
- Segment long documents and preserve stable citations.
- Detect repeated and contradictory claims.
- Cache extraction by source hash and extractor version.

#### Problem and pattern analysis

- Run problem understanding and pattern hypotheses in parallel.
- Return patches rather than mutating the graph.
- Reuse existing pattern profiles, graph pattern detection, and capability registry.
- Keep pattern matches separate from generation support.

#### Planner pilot

- Add shadow-mode contract, state, and asset-flow proposal generation.
- Use an immutable base revision for all parallel planners.
- Add a deterministic reconciler that records conflicts.
- Normalize graph and legacy planner module identifiers and verify capability parity before graph edits can affect a generation plan.
- Do not route generation from these proposals in P0.

#### Validation and confidence

- Add graph integrity, responsibility coverage, state ownership, and asset source/sink checks.
- Replace self-reported node confidence as the sole signal with evidence-aware confidence.
- Mark critical unknowns as generation-blocking.
- Retain support assessment as the backend source of truth.

#### Review

- Extend `spec_review` to show protocol summary, contracts, state, asset flow, patterns, constraints, assumptions, and conflicts.
- Extend graph editing beyond parameter updates to validated node and edge additions, removals, and relationship changes.
- Preserve existing confirm and modify transitions.
- Store user edits as new revisions.
- Keep the existing legacy projections in the payload.

#### Persistence

- Replace the in-memory-only architecture history with a durable revision store suitable for review and generation traceability.
- Preserve immutable approved revisions and parent links.
- Treat the existing graph version counter as compatibility metadata, not revision history.

#### Evaluation corpus

Create a versioned corpus containing:

- Short supported single-pattern prompts
- Existing multi-pattern benchmark prompts
- GitHub README-style specifications
- Hackathon bounties
- Whitepaper excerpts
- Adversarially ambiguous and contradictory inputs

Human labels must include actors, assets, contract responsibilities, state ownership, transactions, constraints, trust assumptions, and unknowns.

### P0 deliverables

- Versioned protocol architecture schema
- Source bundle and provenance contract
- Architecture patch and reconciliation contract
- Shadow-mode problem, pattern, contract, state, and asset planners
- Deterministic architecture validators
- Extended review payload and revision semantics
- Architecture extraction benchmark and baseline report
- Compatibility projections to current specification and planning models

### P0 exit criteria

- Existing single-pattern regression suite is unchanged when architect features are disabled.
- Current guided clients can ignore new fields without failure.
- At least 90% of explicit actors, assets, and numeric constraints are recovered on the labeled pilot corpus.
- Critical unsupported assumptions are introduced in fewer than 2% of corpus cases.
- Every graph claim shown as source-explicit has a valid source span.
- Planner conflicts are surfaced rather than silently resolved.
- Review edits round-trip without losing graph information.
- P95 pre-review latency is measured separately for short prompts and long documents.

### P0 effort

Approximately 6–9 engineer-weeks, parallelizable across schema/backend, extraction/evaluation, and frontend review work.

### P0 rollback

Disable planner and review extensions. Existing guided `ConstraintGraph` and all legacy generation paths continue operating. Stored P0 architectures remain readable but do not drive generation.

## P1 — Guided architecture planning

### Goal

Make the architecture artifact useful and editable for real guided sessions while preserving the existing generation compatibility boundary.

### Scope

#### Contract boundary planner

- Recommend contract count and responsibility boundaries.
- Model custody, authorization, lifecycle, and upgrade domains.
- Present merge/split alternatives and rationale.
- Reject impossible synchronous cross-contract assumptions.

#### State planner

- Classify immutable metadata, mutable NFT commitments, FT state, BCH value, shared state, derived state, and off-chain state.
- Assign ownership and mutation authority.
- Model initialization, transitions, continuation, and terminal states.

#### Asset-flow planner

- Model BCH, FT, NFT, mint, burn, change, fee, recovery, and continuation flows.
- Add deterministic conservation and category checks.
- Expose an editable graph.

#### Interaction planner

- Produce deploy, fund, deposit, claim, refund, migrate, upgrade, and recover transactions as applicable.
- Model partial order, phases, and alternate branches.
- Validate reachability and input/output roles.

#### Constraint planner

- Extract source constraints independently from code.
- Attach constraints to protocol, contract, transaction, state, asset, or path scope.
- Add deterministic authorization, time, amount, conservation, category, and bypass checks.

#### Human review policy

- Require approval for multi-contract, high-impact, low-confidence, experimental, and unsupported architectures.
- Keep review optional for supported high-confidence single-pattern prompts.
- Explain the impact of edits before applying them.
- Preserve backend-authored composition support and simpler alternatives.

#### Incremental re-planning

- Determine which planner domains are invalidated by each edit.
- Re-run only affected planners.
- Preserve confirmed nodes unless a deterministic conflict requires reopening them.

### Generation behavior in P1

Generation continues through the existing graph-to-spec/module compatibility projection.

This means P1 can improve understanding and prevent unsafe generation, but it does not claim complete multi-contract generation. Unsupported compositions remain saveable and reviewable but blocked.

### P1 deliverables

- Editable contract/state/asset/interaction views
- Deterministic reconciliation and incremental re-planning
- Constraint and invariant review
- Mandatory-review policy engine
- Architecture diff and decision history
- Guided-mode telemetry and human edit-distance metrics
- Saved architecture export/import

### P1 exit criteria

- Reviewers accept the recommended contract decomposition without structural edits in at least 70% of supported pilot cases.
- Median human corrections to explicit requirements decrease relative to the current guided specification flow.
- Asset and state validators detect all seeded conservation, ownership, and category contradictions in the evaluation corpus.
- No unsupported composition reaches generation without an explicit existing override.
- P95 short-prompt pre-review latency remains within the agreed product budget.
- Incremental edits do not trigger full document re-extraction unless source material changes.
- Current `spec_turn`, `spec_review`, `spec_confirm`, and `spec_modify` clients remain compatible.

### P1 effort

Approximately 7–11 engineer-weeks, including frontend graph editing and benchmark expansion.

### P1 rollout

1. Internal review-only sessions
2. Opt-in guided beta
3. A small percentage of guided traffic
4. All guided traffic after quality and latency gates pass

Fast generation remains unchanged.

### P1 rollback

Disable parallel planners and render the existing graph review projection. Architectures remain stored; generation still uses the compatibility path.

## P2 — Generation manifest and routed adoption

### Goal

Use an approved architecture to coordinate per-contract generation while preserving existing compile and audit systems.

### Scope

#### Generation manifest

- Create stable contract IDs and architecture revision binding.
- Allocate state, transactions, constraints, and patterns to contract units.
- Define shared constants, token categories, bytecode references, and deployment placeholders.
- Define transaction assembly and contract dependency order.
- Require traceability from every generation obligation to graph node IDs.

#### Per-contract generation orchestration

- Generate contract units from the same approved architecture revision.
- Prevent each contract generation call from rereading and reinterpreting the raw source.
- Share a binding registry across contract units.
- Re-plan only failed contract units when failures do not invalidate architecture.
- Send generated units to the existing compile/repair loop.

#### Consistency gate

Before compilation:

- Verify all manifest obligations are assigned.
- Verify contract references resolve.
- Verify shared constants and token categories agree.
- Verify no critical unknown remains.
- Verify the composition is supported or explicitly experimental with user consent.

#### Automatic routing

- Route obvious simple prompts to the fast path.
- Route document and complex prompts to the architect.
- Permit users to opt into guided architecture for any prompt.
- Permit users to save unsupported architectures without generating.

#### Deprecation

- Demote `effective_mode` to a derived compatibility and benchmark label.
- Stop using flat capability order as the generation architecture.
- Retain legacy mode until parity is proven across supported single-pattern benchmarks.

### P2 deliverables

- Approved-architecture-to-manifest transformation
- Cross-contract binding registry
- Per-contract generation coordinator
- Architecture consistency gate
- Routed fast/guided policy
- Traceability from source to architecture to generated contract
- Migration and deprecation report for legacy planning modules

### P2 exit criteria

- All supported single-pattern benchmarks meet or exceed legacy intent fidelity and compile convergence.
- Selected two-contract pilot protocols generate with no unresolved binding mismatch.
- Every generated contract unit records the approved architecture revision and manifest ID.
- No generator input is reconstructed from raw source after approval.
- Architecture obligation coverage is 100% for generation-blocking constraints.
- Rollback to legacy generation remains possible per request during the stabilization window.
- Compile and audit behavior remains functionally unchanged aside from artifact correlation IDs.

### P2 effort

Approximately 6–10 engineer-weeks for manifest planning, orchestration, compatibility, and hardening. This estimate excludes compile-loop and audit redesign.

### P2 rollout

1. Shadow manifests beside legacy generation
2. Manifest generation for a small allowlist of supported patterns
3. Two-contract pilot cases with explicit support
4. Guided beta with request-level fallback
5. Routed adoption after parity gates

### P2 rollback

Route the request through the legacy projection and generator. Keep the approved architecture and manifest for diagnosis. Do not automatically regenerate through a different architecture revision.

## Backward compatibility details

### API responses

Existing fields remain:

- `specification`
- `constraint_graph`
- `review`
- `planning_report`
- `composition_support`
- `intent_model`

New clients may additionally consume:

- `architecture_schema_version`
- `architecture_id`
- `architecture_revision`
- `source_refs`
- `conflicts`
- `assumptions`
- `decisions`
- `generation_manifest`

Responses should advertise capabilities rather than requiring clients to infer schema support.

### Stored sessions

When loading an older session:

1. Read the legacy specification or graph.
2. Project it into the current schema with `projection` provenance.
3. Mark information that cannot be recovered as unknown.
4. Require review only if the migrated unknowns are material.
5. Never present projected fields as source-explicit.

### Benchmarks

- Pin schema, extractor, registry, prompt, and model versions in every run.
- Keep legacy benchmark mode available until P2 parity.
- Add architecture metrics without changing existing compile and audit scoring.
- Compare routed versus legacy behavior on identical source inputs.

### Feature flags

Existing graph flags should be retained during P0 and P1. New flags should be scoped to planner domains and manifest consumption. Flag names are implementation details, but behavior must support request-level diagnosis and rollback.

## Data migration

No bulk destructive migration is required.

Recommended approach:

- Read legacy sessions lazily.
- Create a new architecture revision on first guided interaction.
- Preserve the original serialized object and migration metadata.
- Use deterministic projection wherever possible.
- Do not backfill source spans that were never stored.
- Keep manifest records immutable once generation starts.

Architecture revisions should be append-only. User-visible deletion policy may remove an architecture, but internal mutation of a historical approved revision would break traceability.

## Observability

Record metrics by input class and rollout mode:

- Source size and section count
- Planner latency, token usage, cache hit rate, and failure rate
- Patch acceptance, rejection, and conflict counts
- Node and edge counts by category
- Critical unknown count
- Clarification count and human review duration
- Human edit distance and decomposition changes
- Support status
- Manifest obligation coverage
- Generation intent fidelity
- Existing compile convergence and audit outcome, correlated but not redefined

Log architecture IDs and revisions, not full private source text. Source retention and redaction policies must be explicit before whitepaper or repository ingestion is enabled broadly.

## Risk register

### P0 risks

#### Schema overreach

Impact: The team models every possible protocol before validating extraction.

Mitigation: Ship only contract, state, transaction, asset flow, provenance, assumptions, conflicts, and the already-approved constraint categories. Defer full predicate ASTs and exotic policy types.

#### Uncalibrated confidence

Impact: Review gating is based on persuasive but meaningless scores.

Mitigation: Use confidence bands and materiality first; calibrate numeric scores from labeled data.

#### Dual source of truth

Impact: `ContractSpecification` and the architecture diverge.

Mitigation: Architecture is authoritative; legacy models are projections with tests.

### P1 risks

#### Planner disagreement

Impact: State and asset ownership become inconsistent.

Mitigation: Immutable snapshots, deterministic patch reconciliation, and surfaced conflicts.

#### Review fatigue

Impact: Users accept architectures without reading them.

Mitigation: Route simple prompts around mandatory review and prioritize critical unknowns over exhaustive questions.

#### Over-decomposition

Impact: Generated systems become unnecessarily complex.

Mitigation: Require boundary rationale and present merge alternatives.

#### Unsupported architecture confusion

Impact: Users assume a saved graph can be generated.

Mitigation: Keep representability and generation support as separate visible states.

### P2 risks

#### Cross-contract drift

Impact: Individually generated contracts disagree on categories, commitments, or identifiers.

Mitigation: One approved revision, one manifest, stable IDs, and a shared binding registry.

#### Compatibility projection masks loss

Impact: Rich architecture collapses silently into legacy generation.

Mitigation: Obligation coverage diagnostics and no P2 manifest routing when the projection is lossy.

#### Benchmark regressions

Impact: Simple patterns become slower or less reliable.

Mitigation: Preserve fast path and require per-pattern parity before routing changes.

#### Rollback changes meaning

Impact: Falling back to legacy generation produces code for a different interpretation.

Mitigation: Fallback is allowed only when the compatibility projection is validated and shown to the user; otherwise return unsupported rather than generating.

## Ownership

Recommended workstream ownership:

- Architecture schema and reconciliation: platform/specification team
- BCH state, asset, and interaction validators: smart-contract domain team
- Extraction, planner prompts, and evaluation: applied AI team
- Review UI and architecture editing: frontend/product team
- Compatibility and generation manifest: generation team
- Security sign-off on constraints and trust models: security architecture
- Benchmark and rollout gates: quality/evaluation

No team should own a private fork of the graph schema.

## Decision gates

### Gate after P0

Proceed only if extraction is source-grounded, critical assumptions are not silently invented, and backward compatibility is demonstrated.

### Gate after P1

Proceed only if human review shows lower correction cost than the current guided flow and deterministic validators catch seeded architecture defects.

### Gate after P2 pilot

Expand routing only if supported pattern parity is maintained and multi-contract bindings remain consistent through the existing compile and audit pipeline.

## Recommended sequence

```text
P0: represent and measure
  source provenance
  canonical schema
  shadow parallel planners
  reconciliation
  validators
  review revisions

P1: review and refine
  contract/state/asset/interaction planning
  constraint planning
  editable architecture
  mandatory-review policy
  incremental re-planning

P2: generate from approval
  generation manifest
  stable cross-contract bindings
  per-contract orchestration
  consistency gate
  routed adoption
```

## Final migration recommendation

Adopt the architect incrementally through the existing guided specification seam.

P0 must establish faithful representation and evidence. P1 must prove that humans can efficiently review and correct the architecture. P2 may then use an approved architecture to coordinate generation. Skipping directly to parallel per-contract generation would amplify inconsistency rather than solve it.

The legacy fast path should remain until graph-native generation demonstrates parity. Unsupported architectures should be valuable as saved and reviewable specifications even before NexOps can generate them.
