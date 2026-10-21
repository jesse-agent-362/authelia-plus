<!--
SPDX-FileCopyrightText: 2026 Authelia
SPDX-FileCopyrightText: 2026 authelia-plus contributors

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

__authelia-plus__ is a fork of [Authelia] that adds OpenID Connect logout, user session management and a few smaller
features on top of an upstream release. This policy covers the code the fork adds. Everything else is Authelia's code
and goes to Authelia under [their security policy][upstream policy].

## Reporting a vulnerability

Report privately through GitHub: [report a vulnerability]. Please don't open an issue, discuss it in public, or tell
third parties until the fix is released.

A report should include:

1. The authelia-plus version or commit, and the configuration needed to trigger the issue.
2. Steps to reproduce, and a working proof of concept against your own instance.
3. The impact in practice: what an attacker gains, and what they need beforehand.
4. A CVSS 4.0 vector, if you have one. We set the final rating.

If you used generative AI anywhere in finding, describing, reproducing or fixing the issue, say how. A person must
have checked the report and run the proof of concept. Reports that weren't checked this way are closed without a
reward.

## In scope

The code authelia-plus adds or changes on top of the upstream release it's built on. For a release
`v<upstream>-plus.<n>`, that is the diff between upstream's `v<upstream>` tag and our tag. Today that means:

- OpenID Connect RP-initiated logout (`end_session_endpoint`) and back-channel logout.
- User sessions: the `/api/plus/sessions` API, the Sessions page in the settings, the
  `authelia storage user sessions` commands, and how sessions and their grants are recorded and revoked.
- The operator stylesheet, `custom.css` served from `server.asset_path`.
- Our build and release workflows and the images they publish.

A bug in upstream Authelia code that our changes don't touch is out of scope here. Please report it to
[Authelia][upstream policy] instead.

## Bug bounty

Valid, in-scope reports are rewarded by severity:

| Severity | CVSS 4.0 | Reward | Examples |
|:--------:|:--------:|:------:|:---------|
| Critical | 9.0–10.0 | 1,000 USDC | Account takeover, or a bypass of authentication or the second factor |
| High | 7.0–8.9 | 300 USDC | A revoked or logged out session that keeps access; revoking another user's session |
| Medium | 4.0–6.9 | 100 USDC | Reading another user's sessions; a forced logout with real impact |
| Low | 0.1–3.9 | Credit only | |

The bounty has a total budget of **2,000 USDC**. Once it's spent, rewards pause and this page says so. Reports are still
welcome while it's paused, and are credited.

Rules:

- The first valid report of an issue is rewarded. Duplicates and issues we already know of are not.
- One reward per root cause, at the severity of its worst impact.
- Rewards are paid once the fix is released.
- The rating and the reward are decided by the maintainer. A rating can move with the impact shown in practice.
- Test only on instances you own. Don't test against anyone else's deployment, including ours.
- We may change or end the bounty at any time. A report is handled under the terms in place when it was submitted.

Out of scope for rewards:

- Denial of service and rate limiting.
- Output from automated scanners without a working exploit.
- Issues that need a misconfiguration the documentation advises against, or administrator access.
- Social engineering, phishing, and physical access.
- Missing headers or best practices with no demonstrated impact.
- Vulnerabilities in dependencies or in upstream Authelia code, which go to those projects.

### Payment

authelia-plus has no company behind it. Rewards are paid by the maintainer personally, in USDC only:

- To an address you give privately in the advisory, on Ethereum or Base, your choice.
- The address is confirmed first with a small test transfer, as a payment sent on the wrong network is lost.
- We pay the network fee.
- Taxes on a reward are yours.
- We can't pay where the law prohibits it, for example under sanctions, and we don't pay to sanctioned addresses.

## Safe harbour

If you research in good faith and follow this policy, we won't take legal action against you or report you to the
authorities, and we consider the research authorised. Good faith means you test only your own instances, don't access,
change or keep other people's data, don't degrade anyone's service, and give us reasonable time to fix the issue before
you disclose it.

## Process

1. We aim to acknowledge a report within 5 days and to confirm or reject it within 14 days.
2. We reproduce the issue, rate it, and agree the details with you.
3. We fix it and release the fix. Where possible you get to try it first.
4. We publish a [security advisory], with a CVE when one is warranted, and credit you unless you prefer otherwise.
5. A reward, if any, is paid.

[Authelia]: https://github.com/authelia/authelia
[upstream policy]: https://www.authelia.com/policies/security/
[report a vulnerability]: https://github.com/man15h/authelia-plus/security/advisories/new
[security advisory]: https://github.com/man15h/authelia-plus/security/advisories
