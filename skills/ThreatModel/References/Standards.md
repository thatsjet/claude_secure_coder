# Standards

Cited sources for every framework and pattern used by the ThreatModel skill.
Listed for the human reader; the skill does not fetch these at runtime.

## OWASP Top 10:2025

- URL: <https://owasp.org/Top10/>
- The canonical list of the most critical web application security risks,
  updated by OWASP. Used by this skill as a sanity check that the threat
  model covers each top-ten category.

## CWE Top 25 (2024)

- URL: <https://cwe.mitre.org/top25/>
- MITRE's annual ranking of the most dangerous software weaknesses. Used by
  this skill when mapping a STRIDE category to specific CWE identifiers in
  the verification probes.

## OWASP AST10 (Agentic Skills Top 10, 2026)

- URL: <https://owasp.org/www-project-agentic-skills-top-10/>
- OWASP's emerging top-ten list of risks specific to agentic skills and LLM
  tool use. Used by this skill as cross-reference for the MAESTRO Frameworks
  and Ecosystem layers.

## OWASP ASVS 5.0

- URL: <https://owasp.org/www-project-application-security-verification-standard/>
- The Application Security Verification Standard. Provides verifiable
  control requirements at three levels. Used by this skill as the source
  catalogue for ISC text on traditional application controls (sessions,
  authentication, input validation, cryptography).

## CSA MAESTRO

- URL: <https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro>
- The Cloud Security Alliance's Multi-Agent Security Threat Reference and
  Operations framework, published February 2025. Defines the seven layers
  used by the MAESTRO workflow.

## Microsoft STRIDE

- URL: <https://learn.microsoft.com/en-us/security/engineering/stride>
- Microsoft's threat-modeling taxonomy: Spoofing, Tampering, Repudiation,
  Information Disclosure, Denial of Service, Elevation of Privilege.
  Defines the categories used by the STRIDE workflow.

## NIST SSDF

- URL: <https://csrc.nist.gov/Projects/ssdf>
- NIST's Secure Software Development Framework (SP 800-218). Used by this
  skill as the cross-reference for shift-left process integration: where
  threat modeling fits in the SDLC and what artifacts it produces.

## SEI CERT Secure Coding

- URL: <https://wiki.sei.cmu.edu/confluence/display/seccode>
- The Software Engineering Institute's Secure Coding standards. Used by
  this skill as the source for language-specific mitigation patterns where
  a generic STRIDE mitigation needs to land in real code.

## OWASP Cheat Sheet Series

- URL: <https://cheatsheetseries.owasp.org/>
- A curated set of concise, technology-aligned guides on specific control
  areas (authentication, authorization, input validation, cryptography,
  logging, etc.). Used by this skill as the source for canonical ISC
  phrasings.
