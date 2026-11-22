import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from fastapi.testclient import TestClient
import app.main as main

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB", str(tmp_path / "test.sqlite"))
    monkeypatch.setattr(main, "SECRET", b"unit-test-secret-long-enough-for-hmac-123456")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "AdminPass123")
    monkeypatch.setattr(main, "validate_upstream_url", lambda url: url)
    with TestClient(main.app) as test_client:
        yield test_client

def test_catalog_and_revocation(client):
    admin_login = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"})
    assert admin_login.status_code == 200
    admin_headers = {"Authorization": "Bearer " + admin_login.json()["access_token"]}

    registered = client.post("/users/register", json={"username":"viewer","password":"ViewerPass123"})
    assert registered.status_code == 200
    user_login = client.post("/users/login", json={"username":"viewer","password":"ViewerPass123"})
    user_headers = {"Authorization": "Bearer " + user_login.json()["access_token"]}
    assert client.get("/catalog", headers=user_headers).json() == []

    source = client.post("/admin/sources", headers=admin_headers, json={
        "name":"Test source", "kind":"hls", "endpoint":"https://media.example/"
    }).json()
    video = client.post("/admin/videos", headers=admin_headers, json={
        "source_id":source["id"], "title":"Test video", "playback_ref":"episode/master.m3u8"
    }).json()
    assert client.get("/catalog", headers=user_headers).json() == []

    grant = client.post("/admin/grants", headers=admin_headers, json={
        "user_id":registered.json()["id"], "video_id":video["id"]
    }).json()
    assert len(client.get("/catalog", headers=user_headers).json()) == 1
    ticket = client.post(f"/playback/{video['id']}/ticket", headers=user_headers)
    assert ticket.status_code == 200
    gateway_path = ticket.json()["gateway_path"]

    assert client.post(f"/admin/grants/{grant['id']}/revoke", headers=admin_headers).status_code == 200
    assert client.get("/catalog", headers=user_headers).json() == []
    assert client.get(gateway_path).status_code == 403
    assert client.post(f"/playback/{video['id']}/ticket", headers=user_headers).status_code == 404

def test_roles_are_separate(client):
    admin = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"})
    assert admin.status_code == 200
    user = client.post("/users/register", json={"username":"admin","password":"UserPass123"})
    assert user.status_code == 200
    assert client.post("/users/login", json={"username":"admin","password":"UserPass123"}).status_code == 200
    assert client.post("/admin/login", json={"username":"admin","password":"UserPass123"}).status_code == 401

def test_playlist_urls_are_rewritten_through_gateway(client):
    admin_login = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"}).json()
    admin_headers = {"Authorization": "Bearer " + admin_login["access_token"]}
    user = client.post("/users/register", json={"username":"viewer2","password":"ViewerPass123"}).json()
    user_headers = {"Authorization": "Bearer " + client.post("/users/login", json={"username":"viewer2","password":"ViewerPass123"}).json()["access_token"]}
    source = client.post("/admin/sources", headers=admin_headers, json={"name":"HLS","endpoint":"https://media.example/root/"}).json()
    video = client.post("/admin/videos", headers=admin_headers, json={"source_id":source["id"],"title":"Playlist","playback_ref":"master.m3u8"}).json()
    client.post("/admin/grants", headers=admin_headers, json={"user_id":user["id"],"video_id":video["id"]})
    ticket = client.post(f"/playback/{video['id']}/ticket", headers=user_headers).json()["ticket"]
    playlist = "#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"keys/key.bin\"\n#EXTINF:6,\nsegments/001.ts\n"
    rewritten = main.rewrite_playlist(playlist, video["id"], ticket, "https://media.example/root/master.m3u8")
    assert "https://media.example" not in rewritten
    assert rewritten.count("/media/") == 2
    assert f"ticket={ticket}" in rewritten

def test_expired_grant_does_not_show_video(client):
    admin_login = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"}).json()
    admin_headers = {"Authorization": "Bearer " + admin_login["access_token"]}
    user = client.post("/users/register", json={"username":"expiredviewer","password":"ViewerPass123"}).json()
    user_headers = {"Authorization": "Bearer " + client.post("/users/login", json={"username":"expiredviewer","password":"ViewerPass123"}).json()["access_token"]}
    source = client.post("/admin/sources", headers=admin_headers, json={"name":"HLS","endpoint":"https://media.example/"}).json()
    video = client.post("/admin/videos", headers=admin_headers, json={"source_id":source["id"],"title":"Expired","playback_ref":"expired.m3u8"}).json()
    client.post("/admin/grants", headers=admin_headers, json={"user_id":user["id"],"video_id":video["id"],"expires_at":int(time.time())-5})
    assert client.get("/catalog", headers=user_headers).json() == []
    assert client.post(f"/playback/{video['id']}/ticket", headers=user_headers).status_code == 404

def test_private_upstream_hosts_are_rejected(monkeypatch):
    import socket
    monkeypatch.setattr(main.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(Exception) as err:
        main.validate_upstream_url("https://internal.example/secret.m3u8")
    assert getattr(err.value, "status_code", None) == 400

def test_duplicate_active_grant_is_rejected_and_audited(client):
    admin_login = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"}).json()
    admin_headers = {"Authorization": "Bearer " + admin_login["access_token"]}
    user = client.post("/users/register", json={"username":"grantuser","password":"ViewerPass123"}).json()
    source = client.post("/admin/sources", headers=admin_headers, json={"name":"S","endpoint":"https://media.example/"}).json()
    video = client.post("/admin/videos", headers=admin_headers, json={"source_id":source["id"],"title":"V","playback_ref":"v.m3u8"}).json()
    payload = {"user_id":user["id"],"video_id":video["id"]}
    assert client.post("/admin/grants", headers=admin_headers, json=payload).status_code == 200
    assert client.post("/admin/grants", headers=admin_headers, json=payload).status_code == 409
    logs = client.get("/admin/audit-logs", headers=admin_headers).json()
    assert any(x["action"] == "grant.created" for x in logs)

def test_past_expiry_is_rejected(client):
    admin_login = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"}).json()
    admin_headers = {"Authorization": "Bearer " + admin_login["access_token"]}
    user = client.post("/users/register", json={"username":"pastuser","password":"ViewerPass123"}).json()
    source = client.post("/admin/sources", headers=admin_headers, json={"name":"S","endpoint":"https://media.example/"}).json()
    video = client.post("/admin/videos", headers=admin_headers, json={"source_id":source["id"],"title":"V","playback_ref":"v.m3u8"}).json()
    result = client.post("/admin/grants", headers=admin_headers, json={"user_id":user["id"],"video_id":video["id"],"expires_at":int(time.time())-1})
    assert result.status_code == 422

def test_media_gateway_rewrites_playlist_and_hides_upstream_url(client, monkeypatch):
    class FakeResponse:
        status_code = 200
        headers = {"content-type": "application/vnd.apple.mpegurl"}
        async def aread(self):
            return b"#EXTM3U\n#EXTINF:5,\nseg/001.ts\n"
        async def aclose(self):
            pass
    class FakeClient:
        async def aclose(self):
            pass
    async def fake_upstream(url, headers=None):
        return FakeClient(), FakeResponse(), url

    monkeypatch.setattr(main, "upstream_request", fake_upstream)
    admin_login = client.post("/admin/login", json={"username":"admin","password":"AdminPass123"}).json()
    admin_headers = {"Authorization": "Bearer " + admin_login["access_token"]}
    user = client.post("/users/register", json={"username":"mediaviewer","password":"ViewerPass123"}).json()
    user_headers = {"Authorization": "Bearer " + client.post("/users/login", json={"username":"mediaviewer","password":"ViewerPass123"}).json()["access_token"]}
    source = client.post("/admin/sources", headers=admin_headers, json={"name":"HLS","endpoint":"https://media.example/root/"}).json()
    video = client.post("/admin/videos", headers=admin_headers, json={"source_id":source["id"],"title":"Protected HLS","playback_ref":"master.m3u8"}).json()
    client.post("/admin/grants", headers=admin_headers, json={"user_id":user["id"],"video_id":video["id"]})
    ticket_data = client.post(f"/playback/{video['id']}/ticket", headers=user_headers).json()
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(ticket_data["gateway_path"])
    asset_id = parsed.path.rsplit("/",1)[-1]
    ticket = parse_qs(parsed.query)["ticket"][0]
    result = client.get(f"/media/{video['id']}/{asset_id}", params={"ticket":ticket})
    assert result.status_code == 200
    assert "media.example" not in result.text
    assert "/media/" in result.text
