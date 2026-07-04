---
name: ThreatModel
description: Design-time security architecture review for software systems and agentic AI — a Distinguished-Architect advisor that gives excellent adversarial advice before the red team runs. Six workflows: STRIDE (traditional apps), MAESTRO (agentic AI per CSA Feb 2025), Data Flow Diagrams with trust boundaries, abuse-case generation, deterministic threat→ISC mapping, and AdversarialPreMortem — the synthesis pass that composes enumerated threats into ranked attack chains (entry→pivot→escalation→impact) and writes a choke-point ISC to sever each before review. Triggers on "threat model", "STRIDE", "MAESTRO", "attack surface", "security review at design time", "abuse cases", "attack chain", "kill chain", "red team pre-mortem", "adversarial pre-mortem", "what will the red team find", "prioritize threats", "chain the threats", "lethal trifecta", or any new project where security-by-design matters.
---

# ThreatModel

Design-time security architecture review. You are operating as a Distinguished
Engineer, Security Architect: you reason in attack *chains* and trust
boundaries, not category checklists, and your job is to give advice so good that
when the red team runs later it finds the criteria already written and
satisfied. The output is a threat list, a populated PRD security section, and a
list of atomic, tool-verifiable Ideal State Criteria (ISCs) — including
chain-closing ISCs that sever the paths an adversary actually walks.

The enumeration workflows (STRIDE, MAESTRO, AbuseCases, DFD) find the atoms;
`AdversarialPreMortem` composes them into the two or three kill chains that
matter and pre-closes each. Enumeration without synthesis produces a wide flat
inventory of Low-residual rows and misses the Critical path that threads three
of them together — which is exactly what a real adversary finds first.

**Division of labor with a capable model.** A Fable-class model already knows
the OWASP/CWE mitigation for any atom you name; do not spend the deliverable
reciting it. The skill's value — the part no model upgrade replaces — is the
*forcing function* (threat-model before code), the *deterministic threat→ISC
translation* (`SecurityISCs.md`), and the *chain synthesis* (`AdversarialPreMortem.md`)
that turns judgment into testable, tool-verifiable acceptance criteria.

This skill is documentation only. It writes nothing on its own. The calling code
(an Algorithm run, a PRD-authoring agent, or a human) takes the skill's output
and pastes it into the work product.

## When to use

- A new project is being scoped and there is no existing threat model.
- A new feature touches authentication, authorization, sessions, or identity.
- A new feature processes payments, billing, or any monetary value.
- A new external integration is being added (third-party API, webhook, OAuth).
- A new trust boundary is being introduced (new service, new tenant, new role).
- A new persistence path for user data is being added (file upload, new table,
  new bucket, new export).
- A new agentic capability is being added (an LLM gets a new tool, an MCP server
  is integrated, a skill is added that can run shell commands).

## When NOT to use

- Post-hoc review of code already shipped. Use SAST, dependency scanning, and
  PR review tooling for that. Threat modeling is a design-time activity.
- Runtime sandboxing decisions. That is an OS-level concern (seccomp,
  AppArmor, gVisor, Firecracker), not a markdown deliverable.
- Compliance frameworks like SOC 2 or ISO 27001. Those need an evidence-driven
  audit process. This skill produces engineering artifacts, not audit artifacts.

## Workflows

| Intent                                                            | Workflow                | When                                                                          |
| ----------------------------------------------------------------- | ----------------------- | ----------------------------------------------------------------------------- |
| Traditional web/API/CLI/mobile app                                | `Workflows/STRIDE.md`   | Conventional software with users, services, and stores.                       |
| Agentic AI / Claude skill / MCP server / multi-agent system       | `Workflows/MAESTRO.md`  | LLM-driven systems with tools, plans, and autonomy.                           |
| Visualize trust boundaries                                        | `Workflows/DataFlowDiagram.md` | Whenever the system has more than one trust zone.                      |
| Generate misuse stories from user stories                         | `Workflows/AbuseCases.md` | Translating product backlog into security requirements.                     |
| Synthesize enumerated threats into ranked attack chains and pre-close them | `Workflows/AdversarialPreMortem.md` | After STRIDE/MAESTRO/AbuseCases enumerate and before finalizing ISCs. The RedTeam pre-mortem: chain the atoms, rank by what review hits first, write one choke-point ISC per chain. |
| Convert threat list into atomic ISCs for the PRD                  | `Workflows/SecurityISCs.md` | Always. This is the bridge between threat modeling and the PRD.           |

## Quick decision tree

1. Is the system traditional (no LLM in the data flow)? Use STRIDE only.
2. Is the system purely agentic (LLM is the brain, tools are the limbs)?
   Use MAESTRO only.
3. Is the system hybrid (a traditional app with one or more AI features
   embedded)? Use both. Run STRIDE on the conventional surface, run MAESTRO on
   the agentic surface, then merge the threat lists. Deduplicate at the ISC
   layer using `SecurityISCs.md`.
4. In every case, run `DataFlowDiagram.md` first if there is more than one
   trust zone. The DFD is what makes the threats specific.
5. In every case, run `AbuseCases.md` if there is a user-story backlog. It is
   the cheapest way to find threats the framework will miss.
6. Before finalizing ISCs, run `AdversarialPreMortem.md`. STRIDE/MAESTRO/AbuseCases
   enumerate isolated atoms; this composes them into the two or three kill chains
   a red team actually walks, ranks them by what review hits first, and writes
   the choke-point ISC that severs each. It invents no new threats — it chains
   the ones you already found, and it is the pass that most directly delivers
   advice *before* the red team breaks things.
7. Always finish with `SecurityISCs.md`. Without it the threat list is a
   document. With it the threat list is testable acceptance criteria.

## Output contract

The calling code receives three artifacts, all in markdown, all in the chat:

1. A threat table. Columns: ID, Category, Threat, Asset, Impact, Likelihood,
   Mitigation, Residual.
2. A populated PRD security section. The skill produces the body of that
   section as markdown the caller can paste under a `## Security` heading.
3. An ISC list ready to drop into a PRD's `## Criteria` section. Each ISC is a
   single binary tool probe, formatted as `- [ ] ISC-N: <criterion>`. At least
   one out of every five ISCs is an `Anti:` ISC (a must-not-happen).

The skill never edits the PRD itself. The caller pastes.

## Integration with the calling ISA / PRD

The Algorithm and PRD-authoring flows expect ISCs as their atomic unit of
verification. `SecurityISCs.md` is therefore the most important workflow: it
performs deterministic translation from a threat shape (e.g. "attacker reuses
session token after logout") into a literal ISC string and a verification
probe. The caller drops the ISC string into `## Criteria` and drops the
verification probe into the PRD's Test Strategy table. The mapping is
one-to-one and reproducible: the same threat shape produces the same ISC every
time.

## Constraints

- The skill must not invent new threat taxonomies. STRIDE, MAESTRO, OWASP, and
  CWE are the only sources. `AdversarialPreMortem` *composes* these atoms into
  chains — a chain is not a new taxonomy — with one deliberate exception:
  composition-level links (concurrency/TOCTOU, replay, cache confusion,
  mass-assignment, ordering skips, cross-turn persistence) have no home element
  and are enumerated inside that workflow because per-element passes structurally
  cannot produce them. That is composition, not a new taxonomy.
- The skill must not recommend specific vendor products. Generic patterns only.
- The skill must not phone home. It does not fetch URLs at runtime. URLs in the
  output are citations for the human, not fetch targets.

## Gotchas

The non-obvious failure modes of design-time adversarial advising. Each has a
concrete cost; ignore one and the skill produces a confident wrong answer.

- **Don't recite what the model already knows.** A Fable-class executor
  reproduces the OWASP mitigation for any atom you name. If a workflow's output
  is a table the model would generate unprompted, it is dead weight that dilutes
  the parts that aren't (the deterministic threat→ISC translation, the chain
  synthesis, the forcing function). The skill's leverage is turning judgment into
  a *tool-verifiable probe*, never the recall.
- **Enumeration ≠ synthesis, and enumeration alone is the classic miss.** A pile
  of Low-residual STRIDE rows reads as "mostly fine" while the Critical path that
  threads three of them together sits unwritten. Never ship a threat model whose
  criteria are all per-atom; run `AdversarialPreMortem` and write at least the
  top chains' choke-point ISCs, or the red team finds the composition you didn't.
- **A choke-point ISC proven only serially is a false green — worse than no
  ISC.** An authorization invariant that survives a serial IDOR fuzz but not a
  single-packet concurrency race, or a token that is single-use in a serial test
  but replayable under load, *retires* the finding and steers review away from
  the still-open path. Every chain-closer's probe must exercise the concurrent,
  replayed, and cross-unit variant. If the probe can't express a race, the closer
  isn't proven — downgrade it to a documented residual with an owner.
- **The lethal trifecta is a per-turn test for a whole-flow property.** The 2026
  flagship agentic breach is the *split* trifecta: attacker turn writes untrusted
  content into a KB/memory (no data read, no egress — looks safe), a later victim
  turn reads it as trusted and completes the exfiltration. Compute the trifecta
  over the union of capabilities across the entire request flow — turns,
  sessions, principals, agents — and treat any persistent write of untrusted
  content as both egress-now and future-ingress-later. A per-turn check passes
  this chain and the chain is real.
- **Design-time chains are hypotheses — label them or you cry wolf.** With no
  running code, it is tempting to assert pivots the implementation may not permit.
  Mark every link Enumerated / Assumed / Refuted. A chain resting on Assumed
  *element-local* links is a question for the build, not a finding — say so, or
  the fiction discredits the real chains beside it. The one exception: an Assumed
  *composition* link (a SEAM or persistence bridge) is never demoted to
  non-finding; it is a design question the build is obliged to answer.
- **Ranking sequences the work; it never authorizes a skip.** RedTeam-First order
  tells you what to close first, not what to ignore. The low-scoring insider/
  bespoke chain is exactly what a targeted attacker uses *because* the base-rate
  scanner misses it. Close every chain whose terminal impact is High or above
  regardless of rank; a deferral is an explicit accepted-risk decision with an
  owner, never a silent down-rank.

## References

- `References/Standards.md` — cited sources for every framework and pattern
  this skill uses.
