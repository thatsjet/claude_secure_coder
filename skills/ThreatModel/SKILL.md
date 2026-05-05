---
name: ThreatModel
description: Threat modeling for software systems and agentic AI. Six workflows covering STRIDE (traditional apps), MAESTRO (agentic AI per CSA Feb 2025), Data Flow Diagrams with trust boundaries, abuse-case generation, and deterministic threat→ISC mapping for shift-left security at design time. Triggers on "threat model", "STRIDE", "MAESTRO", "attack surface", "security review at design time", "abuse cases", or any new project where security-by-design matters.
---

# ThreatModel

Threat modeling at design time. Produces a threat list, a populated PRD security
section, and a list of atomic, tool-verifiable Ideal State Criteria (ISCs) ready
to drop into a PRD's `## Criteria` section.

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
6. Always finish with `SecurityISCs.md`. Without it the threat list is a
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
  CWE are the only sources.
- The skill must not recommend specific vendor products. Generic patterns only.
- The skill must not phone home. It does not fetch URLs at runtime. URLs in the
  output are citations for the human, not fetch targets.

## References

- `References/Standards.md` — cited sources for every framework and pattern
  this skill uses.
