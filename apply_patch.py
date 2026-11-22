
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
main_path = ROOT / "server" / "app" / "main.py"
admin_path = ROOT / "apps" / "admin" / "App.js"

if not main_path.exists() or not admin_path.exists():
    print("错误：请把本补丁放到 crossplay-auth 项目根目录（server/ 和 apps/ 同级）。")
    sys.exit(1)

main = main_path.read_text(encoding="utf-8")
admin = admin_path.read_text(encoding="utf-8")

backend_marker = "def asset_url(video_id: str, upstream_url: str, ticket_value: str):"
backend_code = r'''
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


'''
if backend_marker not in main:
    raise SystemExit("未找到后端插入位置，文件版本可能与补丁目标不一致；未修改文件。")
if "def discover_source(source_id" not in main:
    main = main.replace(backend_marker, backend_code + "\n" + backend_marker, 1)

state_marker = "const [sName,setSName]=useState(''),[sKind,setSKind]=useState('hls'),[sEndpoint,setSEndpoint]=useState(''),[editingSourceId,setEditingSourceId]=useState(null);"
if state_marker not in admin:
    raise SystemExit("未找到管理端状态插入位置，未修改文件。")
if "discoveryCandidates" not in admin:
    admin = admin.replace(state_marker, state_marker + "\n const [discoverySourceId,setDiscoverySourceId]=useState(''),[discoveryCandidates,setDiscoveryCandidates]=useState([]),[discovering,setDiscovering]=useState(false);", 1)

handler_marker = " const addVideo=()=>act(async()=>"
handler_code = r'''
 const discoverSource=async(sourceId)=>{
  setDiscovering(true);setDiscoverySourceId(sourceId);setDiscoveryCandidates([]);
  try{
   const result=await api(`/admin/sources/${sourceId}/discover`,'POST',{});
   setDiscoveryCandidates(result.candidates||[]);
   Alert.alert('识别完成',`页面：${result.page_title||'未命名'}\n发现 ${result.count||0} 个公开视频地址。\n\n${result.notice||''}`);
  }catch(e){Alert.alert('识别失败',String(e))}
  finally{setDiscovering(false)}
 };
 const importDiscovered=()=>act(async()=>{
  if(!discoverySourceId||!discoveryCandidates.length)throw Error('没有可导入的视频条目');
  let imported=0;
  for(const item of discoveryCandidates){
   await api('/admin/videos','POST',{source_id:discoverySourceId,title:item.title||'未命名视频',category:item.category||'',description:item.description||'',playback_ref:item.playback_ref,enabled:true});
   imported++;
  }
  setDiscoveryCandidates([]);setDiscoverySourceId('');
  Alert.alert('导入完成',`已导入 ${imported} 个视频条目。`);
 });
'''
if handler_marker not in admin:
    raise SystemExit("未找到管理端函数插入位置，未修改文件。")
if "const discoverSource=async" not in admin:
    admin = admin.replace(handler_marker, handler_code + "\n" + handler_marker, 1)

ui_marker = "<Btn title={editingSourceId?'保存播放源修改':'添加播放源'} onPress={addSource}/>"
ui_addition = ui_marker + r'''
{sources.filter(s=>s.enabled).map(s=><View key={'discover-'+s.id} style={{marginTop:8}}><Btn title={discovering&&discoverySourceId===s.id?'正在识别…':`自动识别：${s.name}`} kind="ghost" onPress={()=>discoverSource(s.id)}/></View>)}
{discoveryCandidates.length>0&&<View style={{backgroundColor:C.panel,padding:14,borderRadius:12,marginTop:14,borderWidth:1,borderColor:C.accent}}>
 <Text style={{color:C.white,fontWeight:'800',fontSize:16}}>识别结果（{discoveryCandidates.length}）</Text>
 <Text style={{color:C.muted,fontSize:11,marginTop:5}}>请先检查识别结果。导入后仍需确认播放源是否允许你使用这些媒体。</Text>
 {discoveryCandidates.map((item,i)=><View key={item.playback_ref} style={{borderTopWidth:1,borderTopColor:C.line,paddingTop:10,marginTop:10}}>
  <Text style={{color:C.white,fontWeight:'700'}}>{i+1}. {item.title}</Text>
  <Text style={{color:C.muted,fontSize:10,marginTop:4}}>{item.category||'未分类'} · {item.playback_ref}</Text>
 </View>)}
 <Btn title={`全部导入视频目录（${discoveryCandidates.length}）`} onPress={importDiscovered}/>
 <Btn title="放弃识别结果" kind="ghost" onPress={()=>{setDiscoveryCandidates([]);setDiscoverySourceId('')}}/>
</View>}
'''
if ui_marker not in admin:
    raise SystemExit("未找到播放源页面按钮位置，未修改文件。")
if "自动识别：" not in admin:
    admin = admin.replace(ui_marker, ui_addition, 1)

main_path.write_text(main, encoding="utf-8")
admin_path.write_text(admin, encoding="utf-8")
print("补丁应用成功：已更新 server/app/main.py 和 apps/admin/App.js")
print("接下来启动后端，在管理端「播放源」页面点击“自动识别”。")
