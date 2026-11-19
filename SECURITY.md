# Security

This repo is reference code for authentication, so we take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately:

1. **GitHub private security advisory** (preferred):
   [Report a vulnerability](https://github.com/deriv-com/keyfall-oss/security/advisories/new) on `deriv-com/keyfall-oss`.
2. **Email**: [security@deriv.com](mailto:security@deriv.com), naming the repository and the affected file.

Include what you found, how to reproduce it, and the impact you expect.

We aim to acknowledge reports within 3 working days and to agree a fix and disclosure date with you.

## Scope

In scope: the code in `reference/`, the demo's behaviour where it would carry over to a real
deployment, and mistakes in the docs that would lead to an insecure setup.

Out of scope: the demo-only fake login (`reference/login_check/fake.py`) used as intended on
localhost, weaknesses of a specific SSO product or MCP client, and missing hardening of your own
infrastructure (TLS, Redis access, secret storage).

## Notes for people adopting this code

- Read [docs/how-it-works.md](docs/how-it-works.md#what-protects-what) for what the design does
  and doesn't protect against.
- Never deploy with `LOGIN_CHECK=fake` or `DEMO_ONLY=1`.
- Keep `MCP_SIGNING_KEY` in a secret manager; anyone with it can mint approval codes.
- Run Redis with a password, TLS across networks and `maxmemory-policy noeviction`, and
  rate-limit the public `/register`, `/authorize` and `/token` endpoints at your proxy.
- List in `MCP_WEB_REDIRECT_DOMAINS` only the websites your agents return to (avoid `*`), and set
  `MCP_CIMD_TRUSTED_HOSTS` to the vendors you use.
- [docs/security-audit.md](docs/security-audit.md) lists what was reviewed before release and
  what was accepted.
