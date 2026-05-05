# AbuseCases

Most product backlogs are written as user stories: "As a user I want X so
that Y." User stories optimize for legitimate value. They almost never
surface adversaries.

An abuse case is a user story written from the attacker's perspective. It
keeps the same structure but inverts the actor and goal. Abuse cases are
cheap, mechanical to generate, and they catch threats that a STRIDE or
MAESTRO walk would miss because the threats are tied to product semantics
rather than to architectural elements.

This workflow runs alongside STRIDE/MAESTRO. Each workflow finds threats the
others miss; running all of them is the point.

## Format

Each abuse case is a single line of structured text plus a defense ISC:

```
As a <bad actor> I want to <bad goal> so that <bad outcome>.
Defense ISC: <atomic, tool-verifiable criterion>
```

Rules:

- The bad actor must come from the catalogue below or from a documented
  threat model addition. Do not invent ad-hoc adversaries.
- The bad goal is what the attacker tries to do, expressed as a verb.
- The bad outcome is the impact on the system or its users.
- The defense ISC is one binary, atomic check. Multi-step defenses become
  multi-line — one ISC per check.

## Bad actor catalogue

| Actor              | Motivation                                              | Typical capability                                                                       |
| ------------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Curious user       | Sees what they can get away with                        | Authenticated user, browser tools, modest scripting                                      |
| Malicious insider  | Profit, revenge, ideology                               | Privileged credentials, knowledge of internals                                           |
| Scripted attacker  | Mass scanning for low-hanging vulnerabilities           | Automation, opportunistic, low budget, broad coverage                                    |
| Targeted attacker  | Going after this specific organization                  | Time, study of the application, willing to chain weaknesses                              |
| Nation-state       | Espionage, disruption                                   | Zero-days, supply-chain access, long timelines, large budget                             |
| Supply chain       | Compromise via a third-party dependency                 | Code commits, package publishing, build-system access                                    |
| Business competitor | Steal customers, IP, or harm reputation                 | Open-source telemetry analysis, social engineering, public-records analysis              |
| Abusive ex-user    | Harm a specific other user (current or former relation) | Account access, knowledge of victim, often legitimate-looking actions used adversarially |

## Translation rules

For every user story, identify the verbs that touch the attack surface. The
ones that recur:

- **read** — list, view, search, export
- **write** — create, update, edit, configure
- **share** — invite, link, email, copy-to-team
- **upload** — file, image, document, attachment
- **download** — export, generate report, copy-to-device
- **delete** — remove, archive, expire
- **invite** — add member, send link, create token
- **link** — connect external account, OAuth, webhook

For each verb in a story, generate the obvious abuse vector:

- read → read someone else's data, enumerate IDs, time-side-channel
- write → write to someone else's resource, escalate role, inject content
- share → share by mistake, share to outside the trust boundary, forge a share link
- upload → upload malicious payload, upload over quota, upload to evade scanning
- download → download more than allowed, download from another tenant, exfiltrate
- delete → delete someone else's data, delete audit trail, mass-delete to harm
- invite → invite to elevate, invite to harass, invite to cost
- link → link a hostile external system, replay an OAuth code, claim a webhook URL

The result is mechanical: per story, list its verbs, walk the abuse vectors,
write each as a structured abuse case with a defense ISC.

## Worked example: a SaaS onboarding flow

Three user stories from a typical SaaS onboarding flow:

### User story 1: "As a new user I want to sign up so that I can use the product."

Verbs: write (account), read (own profile), link (email).

Abuse cases:

```
As a scripted attacker I want to register many accounts so that I exhaust the free tier or scrape it.
Defense ISC: Sign-up endpoint is rate-limited to 5 per IP per hour and behind CAPTCHA after the first attempt.

As a scripted attacker I want to enumerate which emails are already registered so that I can target known users elsewhere.
Defense ISC: Sign-up response is identical for "email taken" and "email accepted, verify your inbox" cases.

As an abusive ex-user I want to register an account using my target's email to lock them out so that they cannot sign up later.
Defense ISC: Account is not provisioned until the email-verification token is exchanged.

As a malicious insider I want to seed an account with elevated privileges via a side door so that I retain access after offboarding.
Defense ISC: New accounts default to the minimum role; role changes require an audited admin action.

As a nation-state I want to harvest the user-agent and IP of every signup so that I can later correlate to other dossiers.
Defense ISC: Signup logs strip IP to /24 prefix after 30 days; retention policy enforced by a scheduled job.

As a curious user I want to inject HTML into my display name so that other users see scripts when my name is shown.
Defense ISC: Display names are escaped before render; CSP forbids inline script from this origin.

As a scripted attacker I want to register accounts using disposable email domains so that I can run bots cheaply.
Defense ISC: Email domain is checked against a disposable-domain list before sending the verification email.
```

### User story 2: "As a team owner I want to invite a teammate so that they can collaborate."

Verbs: invite, share, link.

Abuse cases:

```
As an abusive ex-user I want to mass-invite my target's email to many teams so that they receive harassment in their inbox.
Defense ISC: Invitations to a single email address from across the platform are rate-limited to 5 per 24 hours.

As a curious user I want to invite a non-existent team member so that I can lock the slot and discover other valid emails.
Defense ISC: Invite endpoint does not reveal whether an email is already a user of the platform.

As a scripted attacker I want to forge an invite acceptance link so that I can join a team I was not invited to.
Defense ISC: Invite tokens are 256-bit cryptographic random, server-side single-use, with 7-day TTL.

As a malicious insider I want to invite myself with a personal email and then escalate that account to admin so that I retain back-door access.
Defense ISC: Invites cannot grant a role higher than the inviter's role; admin-level invites require an out-of-band approval.

As a curious user I want to accept an invite that has expired so that I rejoin a team I was removed from.
Defense ISC: Invite tokens that have been redeemed or have passed their TTL are rejected with no role assignment.

As a scripted attacker I want to invite-spam a team's email channel by repeatedly inviting the same address so that I induce alert fatigue or annoyance.
Defense ISC: Each (team, email) pair is rate-limited to 1 outgoing invite per hour.

As a business competitor I want to read the invite link out of a forwarded email and join a competitor's team so that I see their roadmap.
Defense ISC: Invite links bind to the invited email at acceptance time; acceptance from a different account requires the inviter's confirmation.
```

### User story 3: "As a user I want to upload a file so that I can share it with my team."

Verbs: upload, share, read.

Abuse cases:

```
As a scripted attacker I want to upload a 10 GB file so that I exhaust storage or memory.
Defense ISC: Upload endpoint streams to disk and rejects requests exceeding the configured per-file cap before further parsing.

As a curious user I want to upload a file with `..` traversal in its name so that I overwrite another tenant's object.
Defense ISC: Uploaded filenames are sanitized server-side; the storage key is derived from a server-generated UUID, not the user's name.

As a scripted attacker I want to upload an HTML file that runs scripts in the application's origin so that I steal sessions.
Defense ISC: User-uploaded files are served from a dedicated sandbox subdomain with Content-Disposition: attachment and X-Content-Type-Options: nosniff.

As a malicious insider I want to upload a file to a teammate's quota so that they exceed it and I look productive by comparison.
Defense ISC: Each upload is recorded against the uploading user's quota, derived from the session, never from input.

As a targeted attacker I want to upload a file containing malware so that other team members download it.
Defense ISC: Every uploaded file is scanned by an AV engine before being made available for download; quarantined files are flagged in the UI.

As a curious user I want to share a file with someone outside my team via a public link so that I exfiltrate confidential data.
Defense ISC: Share-links can be created only with a configured access level; "public" requires a tenant-level policy that defaults off.

As an abusive ex-user I want to upload abusive content with my target's name in the filename so that the audit log defames them.
Defense ISC: Audit log of uploads stores actor_id and a server-generated reference, not the raw filename, in routine views.

As a scripted attacker I want to upload many small files so that I exhaust the file count rather than file size.
Defense ISC: Each user has a per-day upload count limit independent of the size limit.

As a business competitor I want to upload a poisoned file that triggers a parser bug in the team's downstream tool so that I gain code execution.
Defense ISC: Uploads are stored as opaque bytes; any server-side parsing of user uploads runs in a sandbox with no host bind mounts.
```

The defense ISCs from each abuse case are dropped into `SecurityISCs.md` for
deduplication against the STRIDE / MAESTRO output and renumbered into the
PRD's `## Criteria` section.
