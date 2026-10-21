# authelia-plus

authelia-plus is an unofficial fork of [Authelia](https://github.com/authelia/authelia), not affiliated with or
endorsed by the Authelia project. It adds OpenID Connect logout, user session management and an operator stylesheet
to Authelia, and each release is built on one upstream release: `v4.39.28-plus.1` is upstream `v4.39.28` plus
these changes.

For everything Authelia itself does, see the [Authelia documentation](https://www.authelia.com/).

## Features

- **OpenID Connect RP-Initiated Logout.** The provider advertises an `end_session_endpoint`
  (`/api/oidc/end-session`). A client registers its `post_logout_redirect_uris`, and a logout with a matching
  `id_token_hint` ends the Authelia session and revokes the tokens issued in it.
- **OpenID Connect Back-Channel Logout.** A client with a `backchannel_logout_uri` is sent a Logout Token when a
  session it was authorized in ends. `backchannel_logout_session_required` asks for the `sid` claim.
- **User sessions.** Settings lists the user's sessions, with device, address and last activity. Users can revoke a
  session or sign out of all their other sessions; revoking a session other than the current one asks for a one-time
  code. The portal uses `GET` and `DELETE /api/plus/sessions`.
- **Session revocation from the CLI.** `authelia storage user sessions revoke <username>` revokes every session of a
  user.
- **Operator stylesheet.** A `custom.css` in `server.asset_path` is served at `/static/custom.css` and linked from the
  portal. See [Server Asset Overrides](docs/content/reference/guides/server-asset-overrides.md#customcss).

## Install

Images for `linux/amd64` and `linux/arm64` are published to GHCR. Pin a release by digest; each
[release](https://github.com/man15h/authelia-plus/releases) lists its tag and digest:

```yaml
image: ghcr.io/man15h/authelia-plus:v4.39.28-plus.1@sha256:<digest>
```

A release is a drop-in replacement for the upstream release it is built on. The configuration is the same, plus the
options above. The new tables are created at startup.

## Security

Report vulnerabilities in authelia-plus as described in [SECURITY.md](SECURITY.md), which also covers the bounty. A
vulnerability that also exists in upstream Authelia should be reported to the Authelia project.

## Licence

authelia-plus is licensed under the [Apache License 2.0](LICENSE) and is based on Authelia. This fork modifies
upstream files; the commit history records how.
