---
task: "Review claude_secure_coder for continued relevance given harness maturity; upgrade to Distinguished Security Architect level pre-review advisor"
slug: csc-relevance-upgrade
project: claude_secure_coder
effort: E4
phase: observe
progress: 0/24
mode: algorithm
started: 2026-07-04
updated: 2026-07-04
principal_stated_goal: "this project was last edited in the Opus 4.6 era. Review this skill to see if a) it's still relevant given our existing harness maturity, and b) if it IS relevant make it the strongest pre-review security engineer it can be, think Distinguished Engineer Security Architect level. It must provide excellent advice before the RedTeam has a chance to attempt to break things."
principal_stated_goal_source: prompt
principal_stated_goal_signal: 4
principal_stated_goal_locked: 2026-07-04
density_gate_acknowledged: true
context_sufficient: true
divergence_risk: low
---

# ISA — claude_secure_coder relevance review + Distinguished-Architect upgrade

## Problem

`claude_secure_coder` is a four-layer shift-left security toolkit (Teach → Design → Write → Review) authored in the Opus 4.6 era. Two things have moved since: (1) the executing model is now Fable 5 with a Jan-2026 knowledge cutoff — dramatically stronger at recalling generic OWASP/CWE/language-idiom guidance unprompted, which is most of what the Teach layer (`SecureCoding.md`, 205 lines) currently spends its tokens on; (2) the harness matured — ThreatModel is now MANDATORY at PLAN for E3+ in Algorithm capabilities (the patches targeted v6.4.0; live is v6.23.0), a newer PAI-native `SecurityPipeline.hook.ts` inspector chain (Pattern → Egress → Rules) now runs PreToolUse alongside the csc `VulnPatternHook`, and the SecureCoding context was already migrated to `LIFEOS/USER/SECURITY/` with a digest swap. The toolkit risks two failure modes: teaching a smart model what it already knows (wasted context, BitterPillEngineering fragility), and leaving its highest-value asset — the design-time advisor — at a "competent threat-lister" level rather than the "Distinguished Security Architect who beats RedTeam to the finding" level the principal now needs for AI-security-heavy work.

## Vision

The principal asks the toolkit "is this design sound?" before a line of code exists, and gets back what a Distinguished Security Architect would say in a design review: not a STRIDE checklist, but the two or three attack *chains* an adversary will actually walk, the trust-boundary assumption that will break, and the exact testable ISCs that close each path — such that when RedTeam runs later, it finds the criteria already written and satisfied. The Teach layer stops reciting what Fable knows and instead carries only the deterministic gates (which a smarter model cannot reason past) and the non-obvious, agentic-first sharp edges. The euphoric surprise: the toolkit's leverage was never the knowledge — it was the *forcing function and the deterministic floor*, and sharpening those makes it stronger precisely because the model got smarter.

## Out of Scope

- Rewriting the deterministic hooks' matching engine (`vuln-patterns-core.ts`) or the SecurityPipeline inspector chain — behavior is sound; this is a doctrine/content/advisor upgrade, not a hook rewrite.
- Resolving the live-install architecture (csc hooks vs SecurityPipeline overlap) — surfaced as a finding + recommendation, not executed, because it's a config decision on Jet's live `~/.claude` (design-shaping; ask, don't auto-change).
- Adding new external SAST tool integrations or MCP servers.
- Runtime sandboxing / OS-isolation work (correctly out of scope per the skill's own charter).
- Migrating or editing the installed copies under `~/.claude/` — this session edits the *source repo*; install/migration is a separate act.

## Principles

- **Deterministic gates are anti-fragile; recited knowledge is fragile.** A secret-blocking regex survives every model upgrade; an OWASP table competes with what the model already knows. Invest where the model can't reason past the control.
- **The advisor's value is judgment made testable, not knowledge recited.** A threat becomes an asset only when it is an atomic, tool-verifiable ISC. Narrative threat lists are documents; ISCs are acceptance criteria.
- **Design-time beats review-time.** The cheapest place to kill a vulnerability is before it is written. "Before RedTeam" is not a schedule claim — it is where the leverage is.
- **Attackers chain; checklists enumerate.** Distinguished-level analysis names the kill chain (entry → pivot → escalation → impact), not just the isolated categories.
- **Agentic/LLM security is now first-class, not an appendix.** Most of what the principal builds has a model in the trust path; indirect prompt injection and excessive agency are the dominant risks, not a footnote after the "real" web app.
- **BitterPillEngineering applies to security content too.** Every rule that a Fable-class model would apply unprompted is dead weight that dilutes the rules that genuinely change behavior.

## Constraints

- Markdown only for content the skill produces; the skill writes nothing on its own and phones home to nothing at runtime (existing charter — preserved).
- No vendor-product recommendations; STRIDE / MAESTRO / OWASP / CWE / CSA are the only taxonomy sources.
- ISC contract is immovable: atomic, tool-verifiable, concrete, stable-phrased, one binary probe each; ≥1 Anti-ISC per 5.
- Edits land in the source repo `/Users/jet/projects/claude_secure_coder`, not the live `~/.claude` install.
- Backward-compatible: existing five workflows keep their names, contracts, and output shapes; additions are additive.

## Goal

Deliver a defensible relevance verdict for `claude_secure_coder` under current harness+model maturity, then upgrade its design-time advisor to Distinguished Security Architect level: (1) trim the Teach layer of model-redundant recitation and elevate deterministic + agentic content per BitterPillEngineering; (2) add a flagship adversarial pre-review workflow that produces attack-chain analysis and RedTeam-anticipating ISCs; (3) sharpen the ThreatModel skill's framing, routing, and gotchas to operate as a Distinguished-level advisor; (4) surface the live-install drift as a recommendation without silently changing Jet's config.

## Criteria

- [ ] ISC-1: A written relevance verdict names, per layer (Teach/Design/Write/Review), what a Fable-class model + mature harness makes redundant vs. what stays anti-fragile, with a keep/trim/strengthen call each.
- [ ] ISC-2: A new flagship workflow file exists in `skills/ThreatModel/Workflows/` that takes a design and produces attack-chain analysis (entry→pivot→escalation→impact), not a flat category list.
- [ ] ISC-3: The flagship workflow produces, for each attack chain, ≥1 atomic tool-verifiable ISC that closes that chain, in the canonical `- [ ] ISC-N:` / `Anti:` format.
- [ ] ISC-4: The flagship workflow explicitly frames itself as anticipating RedTeam findings (a "what will adversarial review find, and is it already closed?" pre-mortem), directly satisfying the principal's stated goal clause.
- [ ] ISC-5: The flagship workflow includes a worked example on an agentic/LLM system (model in the trust path), reflecting the principal's actual build surface.
- [ ] ISC-6: `SKILL.md` routing table includes the new workflow with a clear "when to use" that distinguishes it from STRIDE/MAESTRO.
- [ ] ISC-7: `SKILL.md` gains a Gotchas section (mandatory per CreateSkill doctrine) capturing ≥4 non-obvious failure modes of design-time security advising.
- [ ] ISC-8: `SKILL.md` description is rewritten to position the skill as a Distinguished-Architect design-time advisor and to trigger on the new workflow's intents.
- [ ] ISC-9: `SecureCoding.md` is trimmed of ≥1 section of generic recitation that a Fable-class model applies unprompted, with the trim justified in-band (BitterPillEngineering call recorded).
- [ ] ISC-10: `SecureCoding.md` elevates agentic/LLM security (AST10 / indirect injection / excessive agency) from a late appendix to first-class prominence.
- [ ] ISC-11: `SecureCoding.md` retains 100% of the *deterministic-gate* and *non-obvious sharp-edge* content (nothing anti-fragile is cut).
- [ ] ISC-12: The live-install drift (csc `VulnPatternHook` + `SecurityPipeline` inspector chain both PreToolUse; SecureCoding already migrated to LIFEOS with digest swap) is documented as a finding with a recommended resolution, in the repo (e.g. `docs/` or the verdict), and NOT auto-applied to `~/.claude`.
- [ ] ISC-13: Every new/edited markdown file is internally consistent: no broken cross-references to workflow filenames or sections.
- [ ] ISC-14: The new workflow's ISCs each name a concrete verification probe (curl/grep/test/query/review), not "manually review" alone, except where human judgment is genuinely irreducible (and then labeled as such).
- [ ] ISC-15: The upgrade is verified against an adversarial pass — an independent agent tries to find a design-review gap the flagship workflow would miss, and either finds none load-bearing or the gap is closed.
- [ ] ISC-16: The relevance verdict gives a clear top-line recommendation the principal can act on in one read (keep-and-upgrade / archive / fold-into-harness), with reasoning.
- [ ] ISC-17: Anti: No edit silently changes any file under `~/.claude/` (Jet's live install/config).
- [ ] ISC-18: Anti: The upgrade must not add generic OWASP/CWE recitation that a Fable-class model already applies unprompted (no re-bloating what BPE trims).
- [ ] ISC-19: Anti: The flagship workflow must not invent a new threat taxonomy — it composes STRIDE/MAESTRO/attack-chain thinking over the existing sources.
- [ ] ISC-20: Anti: No ISC produced by the new workflow is un-probeable ("auth is good") — every one names its falsifier.
- [ ] ISC-21: Anti: No claim that the toolkit is "verified working" in the live harness without a real probe (the edits are to the repo; live behavior is not asserted from code alone).
- [ ] ISC-22: The final response leads with the actionable verdict + what changed, in prose the principal can consume without cross-referencing the ISA.
- [ ] ISC-23: Antecedent: The verdict engages the *specific* harness-maturity facts (Fable model, ThreatModel-mandatory, SecurityPipeline overlap, digest swap) — not a generic "still useful" hand-wave — so it reads as a real Distinguished-Engineer assessment.
- [ ] ISC-24: Anti: Existing five workflows retain their filenames, output contracts, and the deterministic threat→ISC translation table (no silent breakage of the crown-jewel Design layer).

## Test Strategy

| isc | type | check | threshold | tool | anchors_to |
|-----|------|-------|-----------|------|------------|
| ISC-1 | manual | verdict has per-layer keep/trim/strengthen | 4 layers covered | Read | literal |
| ISC-2 | bash | new workflow file present | exists | ls/Read | literal |
| ISC-3 | manual | each chain → ≥1 canonical ISC | all chains | Read | literal |
| ISC-4 | grep | "RedTeam"/"adversar"/"pre-mortem" framing present | ≥1 | Grep | literal |
| ISC-5 | manual | agentic worked example present | 1 | Read | literal |
| ISC-6 | grep | routing row for new workflow | 1 | Grep | literal |
| ISC-7 | grep | "## Gotchas" with ≥4 items | ≥4 | Grep/Read | derived: skill-doctrine |
| ISC-8 | manual | description rewritten + triggers | present | Read | literal |
| ISC-9 | manual | ≥1 recitation section trimmed w/ justification | ≥1 | Read | literal |
| ISC-10 | manual | agentic section elevated | prominent | Read | literal |
| ISC-11 | manual | deterministic + sharp-edge content intact | 100% | Read | derived: anti-fragile-core |
| ISC-12 | grep | drift documented in repo, not in ~/.claude | present | Grep | literal |
| ISC-13 | bash | cross-ref filenames resolve | 0 broken | grep/ls | derived: consistency |
| ISC-14 | manual | probes concrete | all | Read | literal |
| ISC-15 | manual | adversarial agent verdict | no load-bearing gap | Agent | literal |
| ISC-16 | manual | top-line recommendation single-read | present | Read | literal |
| ISC-17 | bash | git status of ~/.claude unchanged by session | 0 csc edits | git/stat | literal |
| ISC-18 | manual | no re-bloat | 0 generic adds | Read | derived: bpe |
| ISC-19 | manual | no new taxonomy | composes existing | Read | literal |
| ISC-20 | manual | every ISC probeable | all | Read | literal |
| ISC-21 | manual | no false live-verified claim | 0 | Read | derived: honesty |
| ISC-22 | manual | response leads with verdict | present | Read | literal |
| ISC-23 | manual | verdict cites specific facts | ≥4 facts | Read | literal |
| ISC-24 | bash | 5 workflow files unchanged in contract | intact | ls/Read | literal |

## Features

| name | satisfies | depends_on | parallelizable | intelligence |
|------|-----------|------------|----------------|--------------|
| Relevance verdict | ISC-1, ISC-16, ISC-23, ISC-12 | | yes | max |
| Flagship AdversarialPreMortem workflow | ISC-2,3,4,5,14,19,20 | | yes | max |
| SKILL.md sharpening | ISC-6,7,8,24 | Flagship workflow | no | high |
| SecureCoding.md BPE trim + agentic elevation | ISC-9,10,11,18 | | yes | high |
| Drift documentation | ISC-12,17 | Relevance verdict | no | medium |
| Adversarial verification | ISC-15,21 | all above | no | max |

## Decisions

- D-1 (2026-07-04, OBSERVE): Scope interpretation — "this skill" reads as the whole `claude_secure_coder` toolkit with the ThreatModel skill as centerpiece, because the four layers are one system and the principal's "pre-review security engineer" framing points at the design-time advisor. Picking whole-toolkit over skill-file-only; low divergence risk.
- D-2 (2026-07-04, OBSERVE): Edits target the source repo, not `~/.claude`. Changing Jet's live install is design-shaping config (Celsius-incident class) — surface and let him install. ISC-17 enforces.
- D-3 (2026-07-04, OBSERVE): Density gate acknowledged passed — signal-4 structural directive, concrete named target, low divergence. No interview fired.
- D-4 (2026-07-04, OBSERVE): The highest-leverage single addition is a flagship "adversarial pre-mortem / RedTeam-preview" workflow — it is the most direct realization of "excellent advice before the RedTeam has a chance to break things." Center the upgrade there.

## Changelog

## Verification
