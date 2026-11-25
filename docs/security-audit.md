# Security audit (pre-release)

A review of Keyfall before it is published as `deriv-com/keyfall-oss`. It covers the code and the
security claims in the docs, at commit `e0c0d94`. Fixes are in the commits that follow it. Each
code fix comes with a test that fails without it; the dependency, CI and docs changes have no
test. The security team's own review comes after this one.

**Result:** no Critical or High findings. 4 Medium, 15 Low, 11 Informational. 24 are fixed
and 6 are accepted with a reason. KF-03 was first fixed as an opt-in setting; after review its
default was made strict (see [Decisions needed](#decisions-needed)).

## Scope

| Area | Files |
|---|---|
| MCP server side | `reference/mcp_server_auth.py`: OAuth provider, CIMD and DCR, tokens, refresh rotation and reuse detection, `caller()`, `audited()`, `build_mcp()` |
| Allow page | `reference/allow_page.py` |
| Login checks | `reference/login_check/*` (Cloudflare Access, Google IAP, Pomerium, oauth2-proxy, the demo-only fake) |
| Admin | `reference/admin.py` |
| Demo | `demo/` (compose file, `Dockerfile`, `demo_server.py`, `allow_app.py`, `smoke_test.py`) |
| Helpers and CI | `docs/media/serve.py`, `.github/workflows/tests.yml`, `requirements*.txt` |
| Claims | `README.md`, `SECURITY.md`, `docs/how-it-works.md` ("What protects what"), `docs/setup.md` |

The parts of the MCP Python SDK 2.3.0 that this code relies on were read as well: the
`/authorize`, `/token`, `/register` and `/revoke` handlers, client authentication and the
bearer-token middleware.

## Method

1. **Manual review, file by file.** Checked against the MCP authorization spec (version
   2026-07-28, including its security considerations), OAuth 2.1 and RFC 9700 (OAuth security
   best current practice). Areas covered:
   - PKCE, mix-up attacks (RFC 9207) and sender-constrained tokens;
   - the two HS256 hand-off JWTs: algorithm pinning, issuers and audiences, expiry, single use
     of `jti`, claim checks;
   - the redirect rules in both copies, tried against case, IDN, userinfo, ports, IPv6, schemes,
     encoded characters and backslashes;
   - CSRF, CSP, framing and HTML escaping on the Allow page;
   - open redirects;
   - CIMD SSRF guards;
   - refresh rotation, the grace window and races in reuse detection;
   - revoke, and what happens when Redis fails;
   - Redis key construction;
   - constant-time comparisons;
   - what reaches logs and the audit stream;
   - JWT checks in the login modules;
   - the fake login's guards;
   - DoS limits.
2. **Tools.** `pip-audit` 2.10.1 and `bandit` 1.9.4, from a virtualenv outside the repo.
3. **Hands-on attacks against the running demo.** The demo ran under `podman compose`, with the
   MCP server on port 8000 and the Allow page on 8001. A script using httpx tried:
   - tampered notes and codes;
   - replaying a code;
   - a PKCE mismatch;
   - redirect tricks;
   - replaying a CSRF token on another note;
   - reusing a refresh token after the grace window;
   - using tokens after a revoke and after a restore;
   - oversized inputs;
   - CRLF in parameters;
   - odd CIMD `client_id` values.

   A separate script raced the reuse detector. After the fixes, the demo was rebuilt from this
   branch and every attack was run again.
4. **Real-network check of the CIMD download.** A pinned connection to the right address
   completed TLS. A pinned connection to another site's address failed with a certificate
   hostname mismatch.

## Findings

Line numbers refer to commit `e0c0d94`. Status: **Fixed** (in code, with a test), **Accepted**
(documented, with the reason) or **False positive**.

| ID | Severity | Where | Finding | Status |
|---|---|---|---|---|
| KF-01 | Medium | `mcp_server_auth.py:511`, `:611` | **A refresh in flight could revive a grant that had just been ended.** Reuse detection, an agent's own revoke and an admin revoke all end a grant. A refresh that was mid-flight at that moment re-created the grant with `HSET`, with no expiry and no `subject`, so the chain lived on. It also wrote an access token that nothing deleted, and `load_access_token` never checked the grant. Against the demo, a thief refreshing in a loop kept the chain in 1 of 12 races. | Fixed. `_issue` WATCHes the grant and writes nothing if it is gone. Every lookup (access, refresh, grace) requires a live grant. Demo after the fix: 0 of 24 races. |
| KF-02 | Medium | `mcp_server_auth.py:681` (the SDK's `/authorize` handler) | **The public MCP host was an open redirector.** The SDK sends `/authorize` errors to the client's `redirect_uri`, and DCR lets anyone register an https one. A link to the MCP host therefore landed on any website, with no click and no sign-in (RFC 9700 §4.11.2). Shown with a missing `response_type`, a bad `scope` and a refused `resource`. | Fixed. A route placed ahead of the SDK's answers errors for website callbacks with a 400. Loopback and app callbacks still get their error redirect. |
| KF-03 | Medium | `mcp_server_auth.py:167`, `allow_page.py:164`, `docs/how-it-works.md:154` | **Consent phishing through open DCR.** Anyone can register an agent whose callback is their own website, then send a signed-in person a link to the Allow page. One click on **Allow** sends a code to that site, and its owner can redeem it, because they chose the PKCE secret. The page names the destination and marks the name as self-declared, but nothing else stops it. The docs called the callback rules an "allowlist". | Fixed. Websites receive codes only when listed in `MCP_WEB_REDIRECT_DOMAINS` (default none; `*` allows any https site). The docs now describe the real rule and this case. |
| KF-04 | Medium | `requirements.txt:2-8` | **Dependency floors allowed versions with published advisories.** These include PyJWT below 2.15 (an algorithm allow-list bypass, unbounded JWKS refetch via `kid`, JWKS redirects), Starlette below 1.3.1 (`request.url` built from an unchecked Host header, which the fake login reads), python-multipart below 0.0.31 and h11 below 0.16 (DoS, request smuggling), and cryptography below 49. The pinned resolution was clean. | Fixed. Floors raised; Starlette and h11 named explicitly. |
| KF-05 | Low | `mcp_server_auth.py:273` | **The CIMD download had no overall deadline.** httpx's 5-second timeout applies to each read, so a server sending a byte every few seconds could hold a fetch, and the `/authorize` request waiting on it, for hours. | Fixed. One 5-second deadline covers DNS, connect and the whole body. |
| KF-06 | Low | `mcp_server_auth.py:278` | **The 10 KB cap counted decompressed bytes.** `aiter_bytes()` inflates gzip before the size check runs, so one network chunk could expand to megabytes in memory first. | Fixed. The download asks for `identity`, refuses any `Content-Encoding` and reads raw bytes. |
| KF-07 | Low | `mcp_server_auth.py:220`, `:383` | **CIMD `client_id` values could carry control characters.** `urlsplit` silently drops tabs and newlines, so a `client_id` with a newline or an escape sequence passed the URL checks and was logged as is (log forging, shown against the demo). Non-ASCII look-alike hosts passed the check too; they failed later only by accident. | Fixed. Only printable ASCII is accepted, and the log line uses `%r`. |
| KF-08 | Low | `mcp_server_auth.py:220` | **CIMD URLs could name any port.** The server's own address could be used to probe ports on public hosts, for example services that trust that address. | Fixed. Port 443 only. |
| KF-09 | Low | `mcp_server_auth.py:255` | **IPv6 forms of internal IPv4 addresses passed the public-address check.** `ipaddress` treats `64:ff9b::/96` (NAT64) and `::a.b.c.d` as global, so on an IPv6-only network with NAT64 a name could resolve to an internal IPv4 address in disguise. | Fixed. The IPv4 address wrapped inside is checked too. |
| KF-10 | Low | `mcp_server_auth.py:388` | **Open DCR stored whatever it was sent, for 90 days.** The demo accepted a 200 KB name and 5,000 redirect URIs. Filling Redis this way blocks sign-ins, and under an `allkeys-*` eviction policy it can push out revoke flags. | Fixed. At most 10 redirect URIs of up to 2,000 characters, and an 8 KB record. The docs now ask for `maxmemory-policy noeviction` and rate limits. |
| KF-11 | Low | `allow_page.py:473` | **A non-ASCII `csrf` value caused a 500.** `hmac.compare_digest` raises on non-ASCII `str` input. | Fixed. Bytes are compared instead. |
| KF-12 | Low | `allow_page.py:408` | **Allow was autofocused, with no defence against click timing.** A stray Enter, or a double-click aimed at a page that opens the Allow page, could approve. | Fixed. Nothing has focus on load, and the buttons ignore clicks for the first 0.7 s (CSS only; the page runs no script). |
| KF-13 | Low | `admin.py:111-122` | **The admin CLI printed outside text as is.** Agent names and audit fields reached the terminal unchanged, so escape sequences could move the cursor or erase lines and hide events from the admin. | Fixed. Non-printable characters are printed as escapes. |
| KF-14 | Low | `mcp_server_auth.py:418`, `:486`, `allow_page.py:381` | **Control and bidi characters in agent names were kept.** They were signed into the note, stored in the grant and shown on the Allow page, where a right-to-left override could garble the headline. | Fixed. Names are cleaned to one printable line before signing, storing or showing. |
| KF-15 | Low | `docs/media/serve.py:22-33` | **The local render helper served the whole repo** (including `.git` and any local `.env`) with no Host check, so DNS rebinding could read it. It also accepted a POST from any site, which could overwrite `docs/img`. | Fixed. Host is checked on every request and Origin on POST. Only `docs/` is served. |
| KF-16 | Low | `allow_page.py:457`, `:467` | **Blocking calls ran inside `async def` handlers.** Sync Redis, the JWKS download and OIDC discovery block, so one slow call stalled every request to the Allow page. | Fixed. The handlers are plain `def`, so they run in FastAPI's thread pool. |
| KF-17 | Low | `mcp_server_auth.py:592` | **`MCP_REFRESH_REUSE_ACTION` failed open.** Any value other than exactly `end_grant`, such as a typo, quietly turned reuse detection into logging only. | Fixed. Only `log` does that; anything else ends the grant. |
| KF-18 | Low | `mcp_server_auth.py:472` | **An admin revoke landing during a code exchange could miss the new grant.** The grant was created after the revoke had already looked for grants, so it came back to life on restore. | Fixed. The flag is read again once the grant exists, and every token needs a live grant (KF-01). |
| KF-19 | Low | `allow_page.py:485-488`, `mcp_server_auth.py:715` | **No `iss` in authorization responses** (RFC 9207). The MCP spec (2026-07-28) says authorization servers SHOULD include it, error responses included, and advertise `authorization_response_iss_parameter_supported`; it is the defence against mix-up attacks (RFC 9700 §4.4), which matter because agents talk to several MCP servers. Keyfall sent neither. | Fixed. The note carries the MCP server's metadata issuer, the Allow page returns it as `iss` with the code and with `access_denied`, `/authorize` error redirects carry it, and the metadata advertises it. |
| KF-20 | Info | `mcp_server_auth.py:167`, `:301`, `allow_page.py:164` | **Python and browsers read some URLs differently.** On raw strings, Python reads `http://evil.com\@127.0.0.1/` as loopback, while a browser reads it as `evil.com`; `%2E` in a host and an empty fragment differ the same way. CIMD documents were checked raw. Not exploitable end to end, because `authorize()` re-checks the normalized URI. | Fixed. Both copies refuse backslashes, whitespace, control and non-ASCII characters, userinfo, `%` in the host and any `#`. Documents are re-checked after normalizing. A test keeps the two copies identical. |
| KF-21 | Info | `mcp_server_auth.py:403`, `allow_page.py:198` | **`code_challenge` was never format-checked.** Any string was accepted; the demo took a 6 KB one. | Fixed. It must be a 43-character base64url S256 challenge. |
| KF-22 | Info | `mcp_server_auth.py:477` | **The used-code marker's lifetime didn't follow the code's expiry.** It lived 300 s by Redis's clock, while the code's `exp` comes from the Allow page's clock, so clock drift could reopen a replay window. PKCE would still be required. | Fixed. The marker is kept until 300 s after the code's own expiry. |
| KF-23 | Info | `.github/workflows/tests.yml:11-13` | **The CI workflow trusted mutable tags.** Actions were pinned by tag, and the checkout token was persisted. | Fixed. Actions are pinned to commits, with `persist-credentials: false`. |
| KF-24 | Info | `README.md:88`, `docs/how-it-works.md:102` | **Claims were broader than the code.** "Nothing long-lived ever reaches a laptop" and "every tool call is logged" overstated it: a refresh token chain lasts up to 14 days, and only `@audited` tools are logged. | Fixed (docs). |
| KF-25 | Info | `login_check/fake.py:21` | **The fake login checks only the Host header.** A remote client can send `Host: localhost`. | Accepted. Demo only, and it needs `DEMO_ONLY=1`. The Host check is what stops DNS rebinding. The demo publishes its ports on 127.0.0.1 only. A peer-address check would be unreliable behind container port forwarding. The docstring now says this. |
| KF-26 | Info | `mcp_server_auth.py:581` | **Each unknown refresh token costs about 0.5 s of Redis polling** (11 GETs; measured 0.58 s) while the grace record is awaited. | Accepted. It is async and holds no thread. Rate limits at the proxy cover volume. |
| KF-27 | Info | `mcp_server_auth.py:398` | **DCR client secrets are stored in Redis as issued.** This applies only when a client asks for `client_secret_post`. | Accepted. A secret alone is useless without a refresh token, and agents register as public clients. The README now says only access and refresh tokens are hashed. |
| KF-28 | Info | `mcp_server_auth.py:668` | **`@audited` records tool arguments**, up to 2,000 characters per field. | Accepted. Setup now tells tool authors to keep secrets and personal data out of arguments. |
| KF-29 | Info | `allow_page.py:466` | **One signed note and CSRF token can be submitted more than once,** giving several codes. | Accepted. Each code works once and only with the agent's PKCE secret, and the note expires within 10 minutes. |
| KF-30 | Info | `mcp_server_auth.py:497` | **Access and refresh tokens are bearer tokens,** not sender-constrained (no DPoP, RFC 9449, or mTLS), which RFC 9700 §2.2 recommends. | Accepted. The MCP spec does not mention sender-constrained tokens and MCP clients don't support them. Exposure is limited by 1-hour access tokens, single-use rotating refresh tokens with reuse detection (KF-01), the 14-day cap and admin revoke. |

### False positives and non-issues

- **bandit B105 and B106 (3 hits, Low).** They flag the strings `"none"` (an auth-method name)
  and `"Bearer"` (a token type), which are not passwords.
- **`http://0x7f000001/cb` registered.** Pydantic normalizes it to `http://127.0.0.1/cb`, the
  same address a browser uses. That is loopback and allowed by design.
- **"CSRF from another note" in a first test run.** Two `/authorize` calls in the same second
  with the same parameters produce identical notes (they carry no nonce). With different notes,
  the CSRF token is refused.

### Checked and found sound

- **Signed tokens.** Both are HS256 only. `alg: none`, HS512, a wrong key, a swapped payload, a
  flipped signature and a missing `iat` are all refused. Issuers and audiences differ, so a code
  can't stand in for a note or the other way round. Notes are refused after 10 minutes and codes
  after 60 s. `jti` is single use through an atomic `SET NX`. `client_id` must match, and `role`
  must be a known role.
- **PKCE and the code.** S256 only. A wrong verifier, a different `redirect_uri` at `/token`, and
  a code presented by another client are all refused.
- **Allow page.**
  - The CSRF token is tied to the person and the note, and is compared in constant time.
  - CSP is `default-src 'none'`, with no script, a limited `form-action`, `frame-ancestors 'none'`
    and `base-uri 'none'`, plus `X-Frame-Options: DENY`, `no-store`, `no-referrer` and `nosniff`.
  - Every dynamic value is HTML-escaped.
  - CRLF in `state` stays encoded in `Location`.
  - It fails closed: if the revoke list can't be read, it answers 503 and shows no button.
- **CIMD SSRF guards.** Loopback, private, link-local and metadata names, and IPv6 loopback, are
  refused before any connection. Redirects are refused. TLS is verified against the vendor's
  name while connecting to the checked address.
- **Refresh and revoke.**
  - Rotation works, and a concurrent refresh within the grace window gets the same pair.
  - Reuse after the grace window ends the grant.
  - Revoke refuses access, refresh and the Allow page.
  - Restore does not bring back old tokens.
- **Redis keys.** They are built from the SSO email (lower-cased), uuid client ids, SHA-256
  hashes and `jti`. No user input reaches a SCAN pattern.
- **Constant-time comparisons.** Tokens are looked up by SHA-256, so there is nothing to compare
  directly. The PKCE challenge is public anyway.
- **Logs.** No token, code or secret is logged. The uvicorn access log holds the signed note,
  which is useless without an SSO session and a click.
- **Login checks.** Each module allows only asymmetric algorithms (RS256 and/or ES256, never
  HS*). `aud` is required, and `iss` is required wherever it is configured. Keys come from the
  configured JWKS URL over https. Unsigned `X-Forwarded-*` headers are ignored, and
  `email_verified` must be `true`; a missing claim is refused unless
  `OIDC_ALLOW_MISSING_EMAIL_VERIFIED=true` (see the security team's review below).
- **Admin CLI.** Revoke and restore normalize the email the same way the servers do.
- **Transport security.** DNS-rebinding protection is off on the MCP server. That is correct for
  a public server that authenticates with bearer tokens.

## Tool results

### pip-audit 2.10.1

- **The resolved set is clean.** `requirements.txt` and `requirements-dev.txt` resolve to 34
  packages with no known vulnerabilities, both before and after the change to the floors.
- **The old floors were not.** The table shows the lowest versions the old `requirements.txt`
  allowed (PyJWT 2.10.1 is the effective floor, because `mcp` 2.3.0 requires it).

| Package | Lowest allowed | Advisories | All fixed by |
|---|---|---|---|
| pyjwt | 2.10.1 | 17 (1 disputed, no fix) | 2.15.0 |
| cryptography | 42.0.0 | 9 | 49.0.0 |
| python-multipart | 0.0.9 | 7 | 0.0.31 |
| starlette (via fastapi 0.110) | 0.36.3 | 7 | 1.3.1 |
| h11 (via uvicorn, httpcore) | 0.14.0 | 1 | 0.16.0 |
| mcp, redis, httpx, fastapi, uvicorn | floor | 0 | |

The new floors (KF-04) start at those versions.

### bandit 1.9.4

`bandit -r reference demo docs/media/serve.py`:

| Run | Lines scanned | Issues |
|---|---|---|
| Audited commit `e0c0d94` | 1,478 | 3 Low (B105 once, B106 twice), all Medium confidence, all false positives (see above) |
| After the fixes | 1,636 | the same 3 false positives, nothing new |

Neither run reported a Medium or High issue.

## Hands-on results against the demo

| Attack | Before | After |
|---|---|---|
| Tampered notes: `alg: none`, a swapped payload, a wrong key, HS512, the code audience, a flipped signature, no `iat`, plain PKCE, a 60 KB note | all 400 | all 400 |
| Tampered codes: `alg: none`, a swapped role, a wrong key, a note used as a code, an unknown role, expired | all 400 | all 400 |
| Code replay, PKCE mismatch, `redirect_uri` mismatch, a code for another client | all 400 | all 400 |
| CSRF token from another note, or empty | 400 | 400 |
| Non-ASCII CSRF token | **500** | 400 |
| `/authorize` errors for an https DCR callback | **302 to the attacker's site** | 400 on the MCP host |
| CRLF in `state` | encoded | encoded |
| DCR with a 200 KB name or 5,000 redirect URIs | **201, stored** | 400 |
| DCR body over 4 MB | 413 | 413 |
| CIMD `client_id` containing a newline or an escape | **refused, but written into the log** | refused before any fetch |
| CIMD on port 6379 of a public host | **connection attempted** | refused before any fetch |
| Refresh token reused after the 30 s grace window | grant ended | grant ended |
| Thief refreshing in a loop while reuse is detected | **chain survived 1 of 12** | 0 of 24 |
| Revoke, then use access and refresh; restore, then use old tokens | refused | refused |
| Fake login with another Host (DNS rebinding) | 403 | 403 |
| `iss` on the Allow and Cancel redirects, and the metadata flag | **absent** | present, equal to the metadata issuer and to `authorization_servers` |

## Decisions needed

1. **The default for `MCP_WEB_REDIRECT_DOMAINS` (KF-03). Decided: no websites unless listed.**
   - Websites now receive codes only when their domain is listed; `*` allows any https site.
   - Agents returning to `localhost` or an app callback are not affected. Agents with a web
     callback fail at `/register` until someone lists their domain.
   - Still open: should production setups keep open DCR at all, or rely on CIMD with
     `MCP_CIMD_TRUSTED_HOSTS`?
2. **Reporting KF-02 upstream.** The open redirect comes from the MCP Python SDK's
   `/authorize` error handling, which every SDK-based server inherits. The MCP spec's security considerations say an
   authorization server SHOULD only redirect automatically to a redirect URI it trusts. Keyfall now works around
   it; an upstream report would fix it for others.
3. **Rate limiting.** It stays the proxy's job. The docs now say so, but nothing in the code
   enforces it.

## Security team review, round 1

The security team reviewed commit `d05310f` and raised two Low findings.

| ID | Finding | Outcome |
|---|---|---|
| VULN-001 | `oauth2_proxy` accepted a token with no `email_verified` claim (it refused only an explicit `false`, the same rule oauth2-proxy itself uses). | Fixed. The claim must be `true` (or `"true"`). `OIDC_ALLOW_MISSING_EMAIL_VERIFIED=true` accepts a missing claim for providers that don't send it; an explicit `false` is always refused. |
| VULN-002 | Revoke flags have no TTL and could be evicted under memory pressure. | Fixed with a startup check: the MCP server reads Redis's `maxmemory-policy` and refuses to start on `allkeys-*`. A `volatile-*` policy starts with a warning (revoke flags are safe there, but sessions and the used-code markers have TTLs and can be evicted), and so does a Redis that won't report its policy. No TTL was added: under a `volatile-*` policy Redis evicts only keys that have one, so a TTL would make the flag evictable, and revoke would end on its own after the TTL. Revoke also deletes the person's grants and tokens at once, and every token needs a live grant, so an evicted flag could not revive an existing session; it could only let the person click Allow again. |

## Security team review, round 2

A wider review of commit `0709672` raised 12 findings (3 Medium, 7 Low, 2 Informational).

| ID | Finding | Outcome |
|---|---|---|
| NP-001 | The demo compose file had a built-in signing key; anyone who read it could sign codes for a demo started without one. | Fixed. The compose file has no key and refuses to start without one; the demo steps create a random key in `demo/.env`. |
| NP-002 | `MCP_DEFAULT_ROLE` gives a role to everyone the SSO proxy lets in. | Fixed. `admin` is never a default role (ignored, with an error in the log); `readonly` or `user` log a warning at startup. The docs say the SSO proxy's policy then decides who gets the role. |
| NP-003 | An unknown `MCP_REFRESH_REUSE_ACTION` was not reported. | Fixed. Startup warns. (Reuse was not invisible before: ending a grant records `grant_ended` with `reason=refresh_token_reuse`.) |
| NP-004 | With `MCP_WEB_REDIRECT_DOMAINS=*`, no extra warning on the Allow page. | Not changed. The default allows no websites, `*` is documented as a last resort, and the page already names the website the code goes to. |
| NP-005 | Redis without TLS or a password is not flagged. | Fixed. Startup warns when `REDIS_URL` points beyond this machine without `rediss://` or a password. The demo's Redis is not published outside the Compose network. |
| NP-006 | The first concurrent oauth2-proxy requests could each fetch OIDC discovery. | Fixed. A lock makes it one fetch. No security effect. |
| NP-007 | Google IAP sends no groups, so it relies on `MCP_DEFAULT_ROLE`. | Same fix as NP-002, plus a pointer in `google_iap.py` to looking groups up with the Cloud Identity groups API. |
| NP-008 | `@audited` records tool arguments as given. | Fixed. Arguments named like secrets are recorded as `***`, and `redact=` lists others. |
| NP-009 | Several workers break MCP sessions; nothing enforces one worker. | Documented in the README. The app can't reliably detect its worker count, and this is a reliability limit, not a security one. |
| NP-010 | The two copies of the redirect checks could drift apart. | Already covered: `test_the_two_copies_are_identical` compares the source of every shared function, and `test_the_two_copies_share_their_constants` the constants. Changing one copy fails CI. |
| NP-011 | The Cloudflare Access check also reads the `CF_Authorization` cookie. | Not changed. The cookie gets the same signature, issuer and audience checks as the header, and anyone reaching the origin directly can set the header as easily as the cookie. |
| NP-012 | No rate limiting in the code. | Not changed. Accepted before (KF-10, KF-26): rate limits belong to the proxy, as the setup guide says. |

## Not covered

- **Real SSO proxies, end to end.** Cloudflare Access, Google IAP, Pomerium and oauth2-proxy were
  tested only with locally signed tokens and stubbed keys.
- **Real MCP clients.** The fixed demo was checked with the smoke test and the attack scripts,
  not with Claude Code, Cursor or Codex.
- **Browser behaviour.** The CSS click delay, CSP enforcement and `form-action` on redirects
  were not checked in a real browser. Their tests check the headers and markup only.
- **NAT64 and IPv6-only networks.** Covered by unit tests only.
- **Production-like infrastructure.** Redis with TLS and ACLs, several replicas, and load or DoS
  testing at scale. Only the one race described above was reproduced.
- **Other code and content.** The MCP SDK beyond the handlers listed in Scope, and
  `docs/explainer/`, `docs/media/*.html`, `skill/` and the other docs, apart from the claims
  listed in Scope.
- **Fuzzing.** None was done.
