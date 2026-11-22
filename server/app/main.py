import os, sqlite3, hashlib, hmac, base64, json, time, secrets, re, socket, ipaddress, asyncio
from contextlib import contextmanager, asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.responses import StreamingResponse, Response
from urllib.parse import urljoin, urlparse
import httpx

DB = os.getenv("DATABASE_PATH", "./crossplay.db")
SECRET = os.getenv("TOKEN_SECRET", "dev-only-change-me").encode()
@asynccontextmanager
async def lifespan(app):
    init()
    yield

app = FastAPI(title="CrossPlay Auth API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

@contextmanager
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

def pw_hash(password: str, salt: Optional[bytes] = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(salt + digest).decode()

def pw_ok(password: str, stored: str):
    raw = base64.urlsafe_b64decode(stored.encode())
    salt, expected = raw[:16], raw[16:]
    actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(actual, expected)

def token(payload: dict, ttl=3600):
    body = dict(payload, exp=int(time.time()) + ttl)
    raw = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).rstrip(b"=")
    sig = hmac.new(SECRET, raw, hashlib.sha256).digest()
    return raw.decode() + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

def decode_token(value: str):
    try:
        raw, sig = value.split(".")
        expected = base64.urlsafe_b64encode(hmac.new(SECRET, raw.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(sig, expected): raise ValueError()
        body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if body["exp"] < int(time.time()): raise ValueError()
        return body
    except Exception:
        raise HTTPException(401, "Invalid or expired session")

def current(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    return decode_token(authorization[7:])

def admin(claims=Depends(current)):
    if claims.get("role") != "admin": raise HTTPException(403, "Admin only")
    return claims

def user(claims=Depends(current)):
    if claims.get("role") != "user": raise HTTPException(403, "User account required")
    return claims

def init():
    if os.getenv("APP_ENV") == "production":
        if len(SECRET) < 32 or SECRET == b"dev-only-change-me":
            raise RuntimeError("Set TOKEN_SECRET to a random value of at least 32 bytes before production deployment")
        if os.getenv("ADMIN_PASSWORD", "change-this-before-deploy") == "change-this-before-deploy":
            raise RuntimeError("Set a strong ADMIN_PASSWORD before production deployment")
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, created_at INTEGER NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_role_username ON accounts(role, username);
        CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, endpoint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS videos(id TEXT PRIMARY KEY, source_id TEXT NOT NULL, title TEXT NOT NULL, category TEXT DEFAULT '', description TEXT DEFAULT '', playback_ref TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, video_id TEXT NOT NULL, expires_at INTEGER, revoked_at INTEGER, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS media_assets(id TEXT PRIMARY KEY, video_id TEXT NOT NULL, upstream_url TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL, detail TEXT DEFAULT '', created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_grants_user_video ON grants(user_id, video_id);
        CREATE INDEX IF NOT EXISTS idx_media_assets_video ON media_assets(video_id);
        """)
        name = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD", "change-this-before-deploy")
        if not c.execute("SELECT 1 FROM accounts WHERE username=?", (name,)).fetchone():
            c.execute("INSERT INTO accounts VALUES(?,?,?,?,?)",
                      (secrets.token_hex(12), name, pw_hash(password), "admin", int(time.time())))

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)

class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(default="hls", min_length=1, max_length=30)
    endpoint: str = Field(min_length=1, max_length=2048)
    enabled: bool = True

class VideoIn(BaseModel):
    source_id: str
    title: str = Field(min_length=1, max_length=240)
    category: str = Field(default="", max_length=80)
    description: str = Field(default="", max_length=2000)
    playback_ref: str = Field(min_length=1, max_length=2048)
    enabled: bool = True

class GrantIn(BaseModel):
    user_id: str
    video_id: str
    expires_at: Optional[int] = None

@app.get("/health")
def health(): return {"ok": True, "service": "crossplay-auth"}

@app.post("/admin/login")
def admin_login(data: Credentials):
    with db() as c: row = c.execute("SELECT * FROM accounts WHERE username=? AND role='admin'", (data.username,)).fetchone()
    if not row or not pw_ok(data.password, row["password"]): raise HTTPException(401, "Incorrect credentials")
    return {"access_token": token({"sub": row["id"], "role": "admin"}), "token_type": "bearer"}

@app.post("/users/register")
def register(data: Credentials):
    uid = secrets.token_hex(12)
    try:
        with db() as c:
            c.execute("INSERT INTO accounts VALUES(?,?,?,?,?)", (uid, data.username, pw_hash(data.password), "user", int(time.time())))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")
    return {"id": uid, "username": data.username}

@app.post("/users/login")
def user_login(data: Credentials):
    with db() as c: row = c.execute("SELECT * FROM accounts WHERE username=? AND role='user'", (data.username,)).fetchone()
    if not row or not pw_ok(data.password, row["password"]): raise HTTPException(401, "Incorrect credentials")
    return {"access_token": token({"sub": row["id"], "role": "user"}), "token_type": "bearer"}

@app.get("/admin/users")
def list_users(_=Depends(admin)):
    with db() as c: rows = c.execute("SELECT id,username,created_at FROM accounts WHERE role='user' ORDER BY created_at DESC").fetchall()
    return [dict(x) for x in rows]

@app.post("/admin/sources")
def add_source(data: SourceIn, _=Depends(admin)):
    sid = secrets.token_hex(12)
    with db() as c:
        c.execute("INSERT INTO sources VALUES(?,?,?,?,?,?)", (sid,data.name,data.kind,data.endpoint,int(data.enabled),int(time.time())))
    return {"id": sid, **data.model_dump()}

@app.patch("/admin/sources/{source_id}")
def update_source(source_id: str, data: SourceIn, _=Depends(admin)):
    with db() as c:
        cur = c.execute("UPDATE sources SET name=?,kind=?,endpoint=?,enabled=? WHERE id=?",
                        (data.name,data.kind,data.endpoint,int(data.enabled),source_id))
        if cur.rowcount == 0: raise HTTPException(404,"Source not found")
    return {"ok":True,"id":source_id}

@app.get("/admin/sources")
def list_sources(_=Depends(admin)):
    with db() as c: rows = c.execute("SELECT * FROM sources ORDER BY created_at DESC").fetchall()
    return [dict(x) for x in rows]

@app.delete("/admin/sources/{source_id}")
def disable_source(source_id: str, _=Depends(admin)):
    with db() as c:
        cur = c.execute("UPDATE sources SET enabled=0 WHERE id=?",(source_id,))
        if cur.rowcount == 0: raise HTTPException(404,"Source not found")
        c.execute("UPDATE videos SET enabled=0 WHERE source_id=?",(source_id,))
    return {"ok":True,"id":source_id,"enabled":False}

@app.post("/admin/videos")
def add_video(data: VideoIn, _=Depends(admin)):
    vid = secrets.token_hex(12)
    with db() as c:
        if not c.execute("SELECT 1 FROM sources WHERE id=? AND enabled=1",(data.source_id,)).fetchone(): raise HTTPException(404,"Enabled source not found")
        c.execute("INSERT INTO videos VALUES(?,?,?,?,?,?,?,?)",
                  (vid,data.source_id,data.title,data.category,data.description,data.playback_ref,int(data.enabled),int(time.time())))
    return {"id":vid, **data.model_dump()}

@app.put("/admin/videos/{video_id}")
def edit_video(video_id: str, data: VideoIn, _=Depends(admin)):
    with db() as c:
        if not c.execute("SELECT 1 FROM sources WHERE id=? AND enabled=1",(data.source_id,)).fetchone(): raise HTTPException(404,"Enabled source not found")
        cur = c.execute("UPDATE videos SET source_id=?,title=?,category=?,description=?,playback_ref=?,enabled=? WHERE id=?",
                        (data.source_id,data.title,data.category,data.description,data.playback_ref,int(data.enabled),video_id))
        if cur.rowcount == 0: raise HTTPException(404,"Video not found")
    return {"ok":True,"id":video_id}

@app.get("/admin/videos")
def admin_videos(_=Depends(admin)):
    with db() as c: rows = c.execute("SELECT id,source_id,title,category,description,playback_ref,enabled,created_at FROM videos ORDER BY created_at DESC").fetchall()
    return [dict(x) for x in rows]

@app.delete("/admin/videos/{video_id}")
def disable_video(video_id: str, _=Depends(admin)):
    with db() as c:
        cur = c.execute("UPDATE videos SET enabled=0 WHERE id=?",(video_id,))
        if cur.rowcount == 0: raise HTTPException(404,"Video not found")
    return {"ok":True,"id":video_id,"enabled":False}

@app.patch("/admin/videos/{video_id}/status")
def update_video_status(video_id: str, enabled: bool, _=Depends(admin)):
    with db() as c:
        cur = c.execute("UPDATE videos SET enabled=? WHERE id=?",(int(enabled),video_id))
        if cur.rowcount == 0: raise HTTPException(404,"Video not found")
    return {"ok":True,"id":video_id,"enabled":enabled}

@app.post("/admin/grants")
def grant(data: GrantIn, claims=Depends(admin)):
    gid = secrets.token_hex(12); now = int(time.time())
    if data.expires_at is not None and data.expires_at <= now:
        raise HTTPException(422, "Expiry must be in the future; leave it empty for permanent access")
    with db() as c:
        if not c.execute("SELECT 1 FROM accounts WHERE id=? AND role='user'",(data.user_id,)).fetchone(): raise HTTPException(404,"User not found")
        if not c.execute("SELECT 1 FROM videos WHERE id=? AND enabled=1",(data.video_id,)).fetchone(): raise HTTPException(404,"Video not found")
        existing = c.execute("""SELECT id FROM grants WHERE user_id=? AND video_id=? AND revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at>?) LIMIT 1""", (data.user_id,data.video_id,now)).fetchone()
        if existing:
            raise HTTPException(409, "This user already has an active grant for this video")
        c.execute("INSERT INTO grants VALUES(?,?,?,?,?,?)",(gid,data.user_id,data.video_id,data.expires_at,None,now))
        c.execute("INSERT INTO audit_logs VALUES(?,?,?,?,?,?,?)", (secrets.token_hex(12),claims["sub"],"grant.created","grant",gid,json.dumps({"user_id":data.user_id,"video_id":data.video_id,"expires_at":data.expires_at}),now))
    return {"id":gid,"user_id":data.user_id,"video_id":data.video_id,"expires_at":data.expires_at}

@app.post("/admin/grants/{grant_id}/revoke")
def revoke(grant_id: str, claims=Depends(admin)):
    now = int(time.time())
    with db() as c:
        cur = c.execute("UPDATE grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL",(now,grant_id))
        if cur.rowcount == 0: raise HTTPException(404,"Active grant not found")
        c.execute("INSERT INTO audit_logs VALUES(?,?,?,?,?,?,?)", (secrets.token_hex(12),claims["sub"],"grant.revoked","grant",grant_id,"{}",now))
    return {"ok":True,"revoked":grant_id}

@app.get("/admin/audit-logs")
def audit_logs(limit: int = Query(100, ge=1, le=500), _=Depends(admin)):
    with db() as c:
        rows = c.execute("SELECT id,actor_id,action,target_type,target_id,detail,created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(x) for x in rows]

@app.get("/admin/grants")
def list_grants(_=Depends(admin)):
    with db() as c:
        rows = c.execute("""SELECT g.*,a.username,v.title FROM grants g
        JOIN accounts a ON a.id=g.user_id JOIN videos v ON v.id=g.video_id ORDER BY g.created_at DESC""").fetchall()
    return [dict(x) for x in rows]

def authorized_video(c, uid, vid):
    now = int(time.time())
    return c.execute("""SELECT v.* FROM videos v JOIN sources s ON s.id=v.source_id
    JOIN grants g ON g.video_id=v.id WHERE v.id=? AND v.enabled=1 AND s.enabled=1
    AND g.user_id=? AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>?)""",(vid,uid,now)).fetchone()

@app.get("/catalog")
def catalog(q: str = "", claims=Depends(user)):
    with db() as c:
        rows = c.execute("""SELECT DISTINCT v.id,v.title,v.category,v.description
        FROM videos v JOIN sources s ON s.id=v.source_id JOIN grants g ON g.video_id=v.id
        WHERE g.user_id=? AND v.enabled=1 AND s.enabled=1 AND g.revoked_at IS NULL
        AND (g.expires_at IS NULL OR g.expires_at>?) AND (?='' OR v.title LIKE ? OR v.category LIKE ?)
        ORDER BY v.title""",(claims["sub"],int(time.time()),q,f"%{q}%",f"%{q}%")).fetchall()
    return [dict(x) for x in rows]

def validate_upstream_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Only public HTTPS media sources are supported")
    if parsed.port not in (None, 443):
        raise HTTPException(400, "Only HTTPS port 443 is supported")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if not ip.is_global:
                raise HTTPException(400, "Private or reserved media hosts are not allowed")
    except socket.gaierror:
        raise HTTPException(400, "Media source host could not be resolved")
    return url


class DiscoveryHTMLParser(__import__("html.parser", fromlist=["HTMLParser"]).HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts = []
        self.meta_title = ""
        self.meta_description = ""
        self.media = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            key = (attrs.get("property") or attrs.get("name") or "").lower()
            content = attrs.get("content", "")
            if key in ("og:title", "twitter:title") and content:
                self.meta_title = content.strip()
            elif key in ("description", "og:description") and content:
                self.meta_description = content.strip()
        if tag.lower() in ("video", "source") and attrs.get("src"):
            self.media.append(attrs["src"].strip())
        if tag.lower() == "meta" and (attrs.get("property") or "").lower() == "og:video":
            if attrs.get("content"):
                self.media.append(attrs["content"].strip())

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data.strip())


def _discovery_walk_json(value, found):
    if isinstance(value, dict):
        kind = value.get("@type", "")
        if kind == "VideoObject" or (isinstance(kind, list) and "VideoObject" in kind):
            raw_url = value.get("contentUrl") or value.get("embedUrl") or value.get("url")
            if isinstance(raw_url, str) and raw_url.strip():
                found.append({
                    "url": raw_url.strip(),
                    "title": str(value.get("name") or "").strip(),
                    "description": str(value.get("description") or "").strip(),
                    "category": str(value.get("genre") or "").strip()
                })
        for child in value.values():
            _discovery_walk_json(child, found)
    elif isinstance(value, list):
        for child in value:
            _discovery_walk_json(child, found)


async def _fetch_public_page(url: str):
    current_url = validate_upstream_url(url)
    timeout = httpx.Timeout(12.0, connect=6.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                 headers={"User-Agent": "CrossPlayAuth-SourceInspector/1.0",
                                          "Accept": "text/html,application/xhtml+xml,application/ld+json,*/*;q=0.5"}) as client:
        for _ in range(4):
            response = await client.get(current_url)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    raise HTTPException(502, "网站返回了无效跳转")
                current_url = validate_upstream_url(urljoin(current_url, location))
                continue
            if response.status_code >= 400:
                raise HTTPException(502, f"网站返回 HTTP {response.status_code}")
            content_type = response.headers.get("content-type", "").lower()
            if not any(x in content_type for x in ("text/html", "application/xhtml", "application/json", "text/plain")):
                raise HTTPException(415, "该地址不是可识别的公开网页")
            body = response.content[:2_000_000]
            return current_url, body.decode(response.encoding or "utf-8", errors="replace")
    raise HTTPException(502, "网站跳转次数过多")


@app.post("/admin/sources/{source_id}/discover")
async def discover_source(source_id: str, _=Depends(admin)):
    with db() as c:
        source = c.execute("SELECT * FROM sources WHERE id=? AND enabled=1", (source_id,)).fetchone()
    if not source:
        raise HTTPException(404, "启用中的播放源不存在")

    page_url = source["endpoint"].strip()
    validate_upstream_url(page_url)
    try:
        final_url, html = await _fetch_public_page(page_url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"读取网站失败：{str(exc)[:180]}")

    parser = DiscoveryHTMLParser()
    parser.feed(html)
    page_title = parser.meta_title or " ".join(parser.title_parts).strip() or source["name"]
    page_description = parser.meta_description

    structured = []
    jsonld_pattern = r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>"
    for match in re.findall(jsonld_pattern, html, flags=re.I | re.S):
        try:
            _discovery_walk_json(json.loads(match.strip()), structured)
        except Exception:
            continue

    raw_urls = list(parser.media)
    media_pattern = r"(?:https?:)?//[^\"'\s<>]+?\.(?:m3u8|mp4)(?:\?[^\"'\s<>]*)?|([^\"'\s<>]+?\.(?:m3u8|mp4)(?:\?[^\"'\s<>]*)?)"
    raw_urls.extend(re.findall(media_pattern, html, flags=re.I))
    raw_urls = [item for item in raw_urls if isinstance(item, str) and item]

    candidates = []
    seen = set()

    def add_candidate(raw_url, title="", description="", category=""):
        raw_url = str(raw_url or "").strip().replace("&amp;", "&")
        if not raw_url or raw_url.startswith(("data:", "blob:", "javascript:")):
            return
        media_url = urljoin(final_url, raw_url)
        try:
            validate_upstream_url(media_url)
        except HTTPException:
            return
        path = urlparse(media_url).path.lower()
        if not (path.endswith(".m3u8") or path.endswith(".mp4")) or media_url in seen:
            return
        seen.add(media_url)
        inferred = title.strip() or page_title
        if inferred == page_title:
            filename = urlparse(media_url).path.rsplit("/", 1)[-1]
            inferred = re.sub(r"[-_]+", " ", re.sub(r"\.(m3u8|mp4)$", "", filename, flags=re.I)).strip() or page_title
        candidates.append({
            "title": inferred[:240],
            "category": category[:80],
            "description": description[:1000] or page_description[:1000],
            "playback_ref": media_url
        })

    for item in structured:
        add_candidate(item.get("url"), item.get("title", ""), item.get("description", ""), item.get("category", ""))
    for raw in raw_urls:
        add_candidate(raw)

    return {
        "source_id": source_id,
        "source_name": source["name"],
        "page_title": page_title,
        "detected_type": "HLS/MP4" if candidates else "网页已读取，未发现直接公开的 HLS/MP4 地址",
        "count": len(candidates),
        "candidates": candidates[:100],
        "notice": "这是公开页面的尽力识别。若网站通过 JavaScript、登录、付费、签名接口或 DRM 提供内容，可能无法识别；不会尝试绕过这些限制。"
    }



def asset_url(video_id: str, upstream_url: str, ticket_value: str):
    aid = secrets.token_urlsafe(18)
    with db() as c:
        c.execute("INSERT INTO media_assets VALUES(?,?,?,?)", (aid, video_id, upstream_url, int(time.time()) + 6 * 3600))
        c.execute("DELETE FROM media_assets WHERE expires_at<?", (int(time.time()),))
    return f"/media/{video_id}/{aid}?ticket={ticket_value}"

async def upstream_request(url: str, headers=None):
    current_url = validate_upstream_url(url)
    client = httpx.AsyncClient(timeout=httpx.Timeout(45.0, connect=12.0), follow_redirects=False)
    for _ in range(6):
        response = await client.send(client.build_request("GET", current_url, headers=headers), stream=True)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            await response.aclose()
            if not location:
                await client.aclose()
                raise HTTPException(502, "Invalid upstream redirect")
            current_url = validate_upstream_url(urljoin(current_url, location))
            continue
        if response.status_code >= 400:
            status = response.status_code
            await response.aclose(); await client.aclose()
            raise HTTPException(502, f"Upstream media returned HTTP {status}")
        return client, response, current_url
    await client.aclose()
    raise HTTPException(502, "Too many upstream redirects")

def rewrite_playlist(text: str, video_id: str, ticket_value: str, base_url: str):
    rewritten = []
    uri_pattern = re.compile(r'URI="([^"]+)"')
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            rewritten.append(line); continue
        if stripped.startswith("#"):
            if stripped.startswith("#EXT-X-KEY:") and "METHOD=" in stripped:
                method = re.search(r'METHOD=([^,]+)', stripped)
                if method and method.group(1) not in ("AES-128", "NONE"):
                    raise HTTPException(415, "DRM-protected playlists are not supported")
            if "URI=\"" in line:
                def replace_uri(match):
                    upstream = validate_upstream_url(urljoin(base_url, match.group(1)))
                    return 'URI="' + asset_url(video_id, upstream, ticket_value) + '"'
                line = uri_pattern.sub(replace_uri, line)
            rewritten.append(line)
        else:
            upstream = validate_upstream_url(urljoin(base_url, stripped))
            rewritten.append(asset_url(video_id, upstream, ticket_value))
    return "\n".join(rewritten) + "\n"

@app.post("/playback/{video_id}/ticket")
def playback_ticket(video_id: str, claims=Depends(user)):
    with db() as c:
        row = authorized_video(c, claims["sub"], video_id)
        if not row: raise HTTPException(404, "Video unavailable")
        source = c.execute("SELECT endpoint,kind FROM sources WHERE id=? AND enabled=1", (row["source_id"],)).fetchone()
    playback_ref = row["playback_ref"]
    upstream = urljoin(source["endpoint"].rstrip("/") + "/", playback_ref)
    validate_upstream_url(upstream)
    ticket_value = token({"sub":claims["sub"],"video":video_id,"scope":"playback"}, ttl=3600)
    path = asset_url(video_id, upstream, ticket_value)
    return {"ticket":ticket_value,"expires_in":3600,"gateway_path":path}

@app.get("/media/{video_id}/{asset_id}")
async def media_gateway(video_id: str, asset_id: str, request: Request, ticket: str = Query(...)):
    claims = decode_token(ticket)
    if claims.get("scope") != "playback" or claims.get("video") != video_id:
        raise HTTPException(403, "Invalid playback ticket")
    with db() as c:
        if not authorized_video(c, claims["sub"], video_id):
            raise HTTPException(403, "Authorization revoked or expired")
        asset = c.execute("SELECT upstream_url,expires_at FROM media_assets WHERE id=? AND video_id=?", (asset_id, video_id)).fetchone()
    if not asset or asset["expires_at"] < int(time.time()):
        raise HTTPException(404, "Media asset expired")
    headers = {}
    if request.headers.get("range"):
        headers["Range"] = request.headers["range"]
    client, upstream_response, final_url = await upstream_request(asset["upstream_url"], headers=headers)
    content_type = upstream_response.headers.get("content-type", "application/octet-stream")
    is_playlist = "mpegurl" in content_type.lower() or urlparse(final_url).path.lower().endswith(".m3u8")
    if is_playlist:
        body = await upstream_response.aread()
        await upstream_response.aclose(); await client.aclose()
        text_body = body.decode("utf-8-sig", errors="replace")
        rewritten = rewrite_playlist(text_body, video_id, ticket, final_url)
        return Response(rewritten, media_type="application/vnd.apple.mpegurl", headers={"Cache-Control":"no-store"})
    response_headers = {}
    for header in ("content-length", "content-range", "accept-ranges"):
        if header in upstream_response.headers:
            response_headers[header.title()] = upstream_response.headers[header]
    async def stream_body():
        iterator = upstream_response.aiter_bytes().__aiter__()
        try:
            while True:
                # Re-check authorization even if the upstream stalls. This short polling
                # interval bounds an already-open stream after an administrator revokes access.
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=3.0)
                    yield chunk
                except asyncio.TimeoutError:
                    pass
                except StopAsyncIteration:
                    break
                fresh_claims = decode_token(ticket)
                with db() as c:
                    still_allowed = authorized_video(c, fresh_claims["sub"], video_id) is not None
                if not still_allowed:
                    break
        finally:
            await upstream_response.aclose()
            await client.aclose()
    response_headers["Cache-Control"] = "no-store"
    return StreamingResponse(stream_body(), status_code=upstream_response.status_code,
                             media_type=content_type, headers=response_headers)
