"""Refresh rotation, the concurrent-refresh grace window, stolen-token detection, revoke."""
from __future__ import annotations

import mcp_server_auth as msa


def test_refresh_rotates_and_old_pair_stops_working(world, monkeypatch):
    monkeypatch.setattr(msa, "REFRESH_GRACE_SECONDS", 0)
    client_id, first = world.connect()
    r = world.refresh(client_id, first["refresh_token"])
    assert r.status_code == 200, r.text
    second = r.json()
    assert second["access_token"] != first["access_token"] and second["refresh_token"] != first["refresh_token"]
    assert world.call(first["access_token"]).status_code == 401
    assert world.call(second["access_token"]).status_code == 200


def test_concurrent_refresh_within_grace_gets_the_same_pair(world):
    client_id, first = world.connect()
    a = world.refresh(client_id, first["refresh_token"]).json()
    b = world.refresh(client_id, first["refresh_token"]).json()
    assert a["access_token"] == b["access_token"] and a["refresh_token"] == b["refresh_token"]
    assert world.call(a["access_token"]).status_code == 200


def test_reused_refresh_token_after_grace_ends_the_grant(world, monkeypatch):
    """A thief and the person both hold the chain: when the old token comes back, both lose it."""
    monkeypatch.setattr(msa, "REFRESH_GRACE_SECONDS", 0)
    client_id, stolen = world.connect()
    thief = world.refresh(client_id, stolen["refresh_token"]).json()   # the thief refreshes first
    assert world.call(thief["access_token"]).status_code == 200
    r = world.refresh(client_id, stolen["refresh_token"])               # the person's agent comes back
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    assert world.call(thief["access_token"]).status_code == 401         # the thief is cut off
    assert world.refresh(client_id, thief["refresh_token"]).status_code == 400
    assert any(f.get("reason") == "refresh_token_reuse" for _, f in world.r.xrange("t:audit"))
    assert not world.r.keys("t:grant:*")


def test_reuse_action_log_only_records_it(world, monkeypatch):
    monkeypatch.setattr(msa, "REFRESH_GRACE_SECONDS", 0)
    monkeypatch.setattr(msa, "REFRESH_REUSE_ACTION", "log")
    client_id, first = world.connect()
    second = world.refresh(client_id, first["refresh_token"]).json()
    assert world.refresh(client_id, first["refresh_token"]).status_code == 400
    assert world.call(second["access_token"]).status_code == 200
    assert any(f["event"] == "refresh_reuse" for _, f in world.r.xrange("t:audit"))


def test_refresh_never_extends_the_grant(world, monkeypatch):
    monkeypatch.setattr(msa, "REFRESH_GRACE_SECONDS", 0)
    client_id, first = world.connect()
    grant = world.r.hgetall(world.r.keys("t:grant:*")[0])
    second = world.refresh(client_id, first["refresh_token"]).json()
    assert second["refresh_token"]
    assert world.r.hgetall(world.r.keys("t:grant:*")[0])["grant_expires_at"] == grant["grant_expires_at"]


def test_agent_revoke_disconnects_it(world):
    client_id, tok = world.connect()
    # mcp 2.x wants the client_secret field even for public clients (empty is accepted).
    r = world.mcp.post("/revoke", data={"token": tok["refresh_token"], "token_type_hint": "refresh_token",
                                        "client_id": client_id, "client_secret": ""})
    assert r.status_code == 200
    assert world.call(tok["access_token"]).status_code == 401
    assert not world.r.keys("t:grant:*")


def test_grant_ended_mid_refresh_stays_ended(world, monkeypatch):
    """Reuse detection or a revoke can end the grant while a refresh is in flight. That refresh
    must not re-create the grant (it used to, with no expiry, so the chain lived on)."""
    monkeypatch.setattr(msa, "REFRESH_GRACE_SECONDS", 0)
    client_id, tok = world.connect()
    real = msa.AllowPageOAuthProvider._issue

    async def ended_first(self, *args):
        await self.end_grant(args[4], reason="test")
        return await real(self, *args)

    monkeypatch.setattr(msa.AllowPageOAuthProvider, "_issue", ended_first)
    r = world.refresh(client_id, tok["refresh_token"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    assert not world.r.keys("t:grant:*") and not world.r.keys("t:access:*") and not world.r.keys("t:refresh:*")


def test_every_token_dies_with_its_grant(world):
    """A token that end_grant missed (written by a request still in flight) is refused anyway."""
    client_id, tok = world.connect()
    world.r.delete(*world.r.keys("t:grant:*"))
    assert world.call(tok["access_token"]).status_code == 401
    assert world.refresh(client_id, tok["refresh_token"]).status_code == 400


def test_revoke_landing_during_code_exchange_wins(world, monkeypatch):
    """The revoke flag is set after the code was checked but before tokens exist: no grant survives."""
    real = msa.AllowPageOAuthProvider._issue

    async def revoked_meanwhile(self, *args):
        out = await real(self, *args)
        await self.redis.set("t:revoked:alice@example.com", "{}")
        return out

    monkeypatch.setattr(msa.AllowPageOAuthProvider, "_issue", revoked_meanwhile)
    client_id, verifier, code = world.sign_in()
    r = world.token(client_id, verifier, code)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    world.r.delete("t:revoked:alice@example.com")       # restore: nothing from before comes back
    assert not world.r.keys("t:grant:*") and not world.r.keys("t:access:*")


def test_a_mistyped_reuse_action_still_ends_the_grant(world, monkeypatch):
    monkeypatch.setattr(msa, "REFRESH_GRACE_SECONDS", 0)
    monkeypatch.setattr(msa, "REFRESH_REUSE_ACTION", "end-grant")     # typo for end_grant
    client_id, first = world.connect()
    second = world.refresh(client_id, first["refresh_token"]).json()
    assert world.refresh(client_id, first["refresh_token"]).status_code == 400
    assert world.call(second["access_token"]).status_code == 401
