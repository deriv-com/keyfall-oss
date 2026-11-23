"""Each login_check example accepts a correctly signed identity token and nothing else."""
from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from login_check import _jwt, cloudflare_access, google_iap, oauth2_proxy, pomerium, signed_in_person

RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC = ec.generate_private_key(ec.SECP256R1())
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class KeyStub:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return SimpleNamespace(key=self.key)


def request(headers=None, cookies=None, host="approve.example.com"):
    return SimpleNamespace(headers=headers or {}, cookies=cookies or {}, url=SimpleNamespace(hostname=host))


def token(key, alg, **claims):
    now = int(time.time())
    return jwt.encode({"iat": now, "exp": now + 300, **claims}, key, algorithm=alg)


@pytest.fixture(autouse=True)
def stub_keys(monkeypatch):
    monkeypatch.setattr(_jwt, "_clients", {
        "https://team.cloudflareaccess.com/cdn-cgi/access/certs": KeyStub(RSA.public_key()),
        google_iap.JWKS_URL: KeyStub(EC.public_key()),
        "https://approve.example.com/.well-known/pomerium/jwks.json": KeyStub(EC.public_key()),
        "https://login.example.com/keys": KeyStub(RSA.public_key()),
    })


def test_cloudflare_access(monkeypatch):
    monkeypatch.setenv("ACCESS_TEAM_DOMAIN", "team.cloudflareaccess.com")
    monkeypatch.setenv("ACCESS_AUD", "aud-tag")
    good = dict(iss="https://team.cloudflareaccess.com", aud="aud-tag", email="bo@example.com",
                custom={"groups": ["mcp-user"]})
    p = cloudflare_access.person(request({"Cf-Access-Jwt-Assertion": token(RSA, "RS256", **good)}))
    assert p.email == "bo@example.com" and p.groups == ("mcp-user",)
    assert cloudflare_access.person(request(cookies={"CF_Authorization": token(RSA, "RS256", **good)}))
    for bad in (token(RSA, "RS256", **{**good, "aud": "other"}), token(OTHER, "RS256", **good),
                token(RSA, "RS256", **{**good, "iss": "https://evil.example.com"})):
        assert cloudflare_access.person(request({"Cf-Access-Jwt-Assertion": bad})) is None


def test_google_iap_has_email_but_no_groups(monkeypatch):
    monkeypatch.setenv("IAP_AUDIENCE", "/projects/1/global/backendServices/2")
    t = token(EC, "ES256", iss=google_iap.ISSUER, aud="/projects/1/global/backendServices/2", email="cy@example.com")
    p = google_iap.person(request({"x-goog-iap-jwt-assertion": t}))
    assert p.email == "cy@example.com" and p.groups == ()
    expired = jwt.encode({"iss": google_iap.ISSUER, "aud": "/projects/1/global/backendServices/2",
                          "email": "cy@example.com", "iat": 1, "exp": 2}, EC, algorithm="ES256")
    assert google_iap.person(request({"x-goog-iap-jwt-assertion": expired})) is None


def test_pomerium(monkeypatch):
    monkeypatch.setenv("POMERIUM_ROUTE_HOST", "approve.example.com")
    t = token(EC, "ES256", aud="approve.example.com", email="di@example.com", groups=["mcp-admin"])
    p = pomerium.person(request({"X-Pomerium-Jwt-Assertion": t}))
    assert p.email == "di@example.com" and p.groups == ("mcp-admin",)
    assert pomerium.person(request({"X-Pomerium-Jwt-Assertion": token(EC, "ES256", aud="x", email="a@b.c")})) is None


def test_oauth2_proxy_checks_the_id_token_not_plain_headers(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://login.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "proxy")
    monkeypatch.setenv("OIDC_JWKS_URL", "https://login.example.com/keys")
    t = token(RSA, "RS256", iss="https://login.example.com", aud="proxy", email="ed@example.com",
              email_verified=True, groups="mcp-user,mcp-readonly")
    p = oauth2_proxy.person(request({"Authorization": f"Bearer {t}"}))
    assert p.email == "ed@example.com" and p.groups == ("mcp-user", "mcp-readonly")
    unsigned = request({"X-Forwarded-Email": "ed@example.com", "X-Forwarded-Groups": "mcp-admin"})
    assert oauth2_proxy.person(unsigned) is None
    unverified = token(RSA, "RS256", iss="https://login.example.com", aud="proxy", email="ed@example.com",
                       email_verified=False)
    assert oauth2_proxy.person(request({"Authorization": f"Bearer {unverified}"})) is None


def test_oauth2_proxy_needs_email_verified_true(monkeypatch):
    """A missing email_verified claim is refused unless OIDC_ALLOW_MISSING_EMAIL_VERIFIED=true."""
    monkeypatch.setenv("OIDC_ISSUER", "https://login.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "proxy")
    monkeypatch.setenv("OIDC_JWKS_URL", "https://login.example.com/keys")
    monkeypatch.delenv("OIDC_ALLOW_MISSING_EMAIL_VERIFIED", raising=False)

    def person(**claims):
        t = token(RSA, "RS256", iss="https://login.example.com", aud="proxy", email="ed@example.com", **claims)
        return oauth2_proxy.person(request({"Authorization": f"Bearer {t}"}))

    assert person() is None
    assert person(email_verified=False) is None
    assert person(email_verified="false") is None
    assert person(email_verified=True).email == "ed@example.com"
    assert person(email_verified="true").email == "ed@example.com"
    monkeypatch.setenv("OIDC_ALLOW_MISSING_EMAIL_VERIFIED", "true")
    assert person().email == "ed@example.com"
    assert person(email_verified=False) is None


def test_unknown_or_missing_setup_refuses_everyone(monkeypatch):
    monkeypatch.setenv("LOGIN_CHECK", "")
    assert signed_in_person(request(host="localhost")) is None
    monkeypatch.setenv("LOGIN_CHECK", "something_else")
    assert signed_in_person(request(host="localhost")) is None
