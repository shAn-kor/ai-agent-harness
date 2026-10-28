# ADR 0003: Mandatory project-local engineering standards

## Status

Accepted

## Context

AI implementation must not proceed without executable lint and architecture
checks. Global rules cannot safely choose a team's conventions, while a missing
project policy is not an acceptable implicit opt-out.

## Decision

`workflowctl start` fails closed unless `.agents/workflow.json` contains an
approved, versioned `standards` contract and explicit `test`, `lint`,
`architecture`, and `build` commands. Detection and scaffolding use the static
`project-standards.json` catalog; no model classifies the repository.

Initialization retains all detected stacks, resolves checked-in build wrappers
or deterministic system-tool fallbacks, and generates a project-local
`.agents/architecture.json`. The architecture gate executes every declared
source-boundary rule. Its SHA-256 digest is part of the approval contract, so a
post-approval rule edit blocks subsequent work until it is approved again.

Personal projects may explicitly initialize an immediately approved contract.
Team projects initialize as pending and require an approval evidence locator
before work can start. All generated configuration remains project-local.

The initial catalog covers Spring/JVM on Gradle or Maven, Node/TypeScript,
Python, Rust, and Go. A rule that matches no production source fails closed; a
forbidden dependency reports the rule, file, and line. Recursive glob matching
covers arbitrary package depth. A matching symlink, non-regular source, or
source beyond the bounded scanner size fails closed instead of being skipped.
Tracked symlink entries are also rejected when their path can intersect a rule's
literal source prefix and the link is a directory or broken, preventing an
unenumerated symlink subtree bypass. A regular symlink file is rejected only
when its own effective include/exclude match selects it.

## Consequences

Projects without standards must bootstrap and, for team governance, approve a
contract before implementation. Existing team configuration remains authoritative
because initialization refuses to overwrite an existing standards block or
explicit command. Template changes are versioned harness changes and are
reviewable as code.
