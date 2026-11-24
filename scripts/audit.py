#!/usr/bin/env python3
"""Audit upstream feeds without executing packages or modifying apps.json."""
import hashlib
import io
import json
import re
import tarfile
import tempfile
import socket
import ipaddress
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit, unquote
from concurrent.futures import ThreadPoolExecutor

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / "audit-output"
MAX_JSON = 4 * 1024 * 1024
MAX_IPK = 160 * 1024 * 1024
EXPERIMENTAL = re.compile(r"(^|[^a-z])(alpha|beta|nightly|testing|experimental|prerelease|preview|rc\d*)([^a-z]|$)", re.I)
PARTIAL = re.compile(r"\b(slopium|cleanframe|hearth|apl launcher|custom launcher|nxe|aurora|ihsplay|bolli)\b", re.I)
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
VERSION = re.compile(r"\d+\.\d+\.\d+")
HASH = re.compile(r"[a-fA-F0-9]{64}")
BLOCK_IDS = {"org.webosbrew.hbchannel", "com.open.hidden.menu", "com.m12c.telnet", "com.aurora.gamestream", "org.mariotaku.ihsplay"}
ALLOWED = {"github.com", "api.github.com", "repo.webosbrew.org", "freemytv.io", "drive.usercontent.google.com", "webosbrew.org"}
SUFFIXES = (".github.io", ".githubusercontent.com")

def safe(url):
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if u.scheme != "https" or u.username or u.password or u.port not in (None, 443):
        raise ValueError("HTTPS required")
    if host not in ALLOWED and not host.endswith(SUFFIXES):
        raise ValueError("host outside allowlist")
    if not all(ipaddress.ip_address(a[4][0]).is_global for a in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)):
        raise ValueError("non-public address")
    return url

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

OPENER = urllib.request.build_opener(Redirect())

def fetch(url):
    # Retry from the ORIGINAL release URL, never from an expired signed redirect.
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlunsplit
    from uuid import uuid4
    from time import sleep
    original = safe(url)
    u = urlsplit(original)
    release = u.hostname == "github.com" and "/releases/" in u.path
    for attempt in range(3):
        target = original
        if release and attempt:
            query = "&".join(filter(None, (u.query, "_audit=" + uuid4().hex)))
            target = urlunsplit((u.scheme, u.netloc, u.path, query, ""))
        try:
            return OPENER.open(urllib.request.Request(safe(target), headers={
                "User-Agent": "webOS-Mega-Repository-audit/3.1", "Accept": "*/*",
                "Cache-Control": "no-cache", "Pragma": "no-cache"
            }), timeout=25)
        except HTTPError as e:
            if attempt == 2 or e.code not in (403, 408, 429, 500, 502, 503, 504, 618):
                raise
            e.close()
        except (URLError, TimeoutError):
            if attempt == 2:
                raise
        sleep(1 + attempt)
    raise RuntimeError("download retry exhausted")

def read_json(url):
    with fetch(url) as r:
        b = r.read(MAX_JSON + 1)
        if len(b) > MAX_JSON:
            raise ValueError("JSON too large")
        return json.loads(b), r.geturl()

def absolute(base, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("missing URL")
    return safe(urljoin(base, value))

def digest(m):
    h = (m.get("ipkHash") or {}).get("sha256")
    if not isinstance(h, str) or not HASH.fullmatch(h):
        raise ValueError("missing SHA-256")
    return h.lower()

def version(v):
    if not isinstance(v, str) or not VERSION.fullmatch(v):
        raise ValueError("invalid or experimental version")
    return tuple(map(int, v.split(".")))

def candidate(item, base):
    m = item.get("manifest")
    mb = base
    if item.get("manifestUrl"):
        manifest_url = absolute(base, item["manifestUrl"])
        ext, mb = read_json(manifest_url)
        # A relative sibling asset belongs to the permanent release URL,
        # not to the temporary signed CDN address used to serve its JSON.
        if urlsplit(manifest_url).hostname == "github.com" and "/releases/download/" in urlsplit(manifest_url).path:
            mb = manifest_url
        if m:
            for k in ("id", "version", "rootRequired"):
                if m.get(k) != ext.get(k):
                    raise ValueError("manifest disagreement: " + k)
            if digest(m) != digest(ext):
                raise ValueError("manifest hash disagreement")
            # Equivalent IPK URLs may differ; the selected bytes must match the common digest.
        m = ext
    if not isinstance(m, dict):
        raise ValueError("missing manifest")
    m = dict(m)
    ident = m.get("id", "")
    title = m.get("title") or item.get("title") or ""
    if not isinstance(ident, str) or not ID.fullmatch(ident) or item.get("id", ident) != ident:
        raise ValueError("invalid or divergent ID")
    version(m.get("version"))
    if m.get("rootRequired") is True:
        raise ValueError("root explicitly required")
    if m.get("rootRequired") is not False:
        # Narrow exceptions backed by the official project's no-root documentation.
        # Only these reviewed versions, publishers and digests may fill an absent flag.
        reviewed = {
            ("com.retroarch.webos", "1.22.2", "0b8ead78b49f02097986a14776d1d90ce856184a11290e8c3640f1001b02d4e3"): (
                "https://github.com/webosbrew/RetroArch",
                "https://repo.webosbrew.org/apps/com.retroarch.webos/"),
            ("org.scummvm.scummvm", "1.3.0", "7160edef1667a1f76fb0573cd7a44d714a423e9b3c8ef4d664822287a3601326"): (
                "https://github.com/RF1705/scummvm-webos",
                "https://repo.webosbrew.org/apps/org.scummvm.scummvm/"),
        }
        evidence = reviewed.get((ident, m["version"], digest(m)))
        if m.get("rootRequired") is not None or not evidence or m.get("sourceUrl", "").rstrip("/") != evidence[0]:
            raise ValueError("root requirement unspecified; manual upstream review needed")
        m["rootRequired"] = False
    if ident in BLOCK_IDS or PARTIAL.search(title) or re.search(r"\b(xbox cloud gaming|better xcloud|better-xcloud)\b", title, re.I):
        raise ValueError("restricted functionality or Xbox client pending dedicated upstream review")
    if re.search(r"technical demo", str(m.get("appDescription", "")), re.I):
        raise ValueError("technical demonstration") 
    if ident in {"com.github.k4zmu2a.space-cadet-pinball"}:
        raise ValueError("restricted functionality or privileged tool")
    ipk = absolute(mb, m.get("ipkUrl"))
    if EXPERIMENTAL.search(" ".join([title, str(item.get("pool", "")), unquote(ipk)])):
        raise ValueError("experimental channel or release")
    digest(m)
    m["ipkUrl"] = ipk
    for k in ("iconUri", "sourceUrl"):
        if m.get(k):
            m[k] = urljoin(mb, m[k])
    p = {"id": ident, "title": title, "manifest": m}
    for k in ("pool", "category", "shortDescription", "requirements", "iconUri", "detailIconUri", "fullDescriptionUrl"):
        if k in item:
            p[k] = urljoin(base, item[k]) if k.endswith(("Uri", "Url")) and isinstance(item[k], str) else item[k]
    return p

def scan_source(url):
    results, errors = [], []
    seen = set()
    try:
        for _ in range(20):
            if url in seen:
                raise ValueError("pagination cycle")
            seen.add(url)
            d, base = read_json(url)
            if not isinstance(d.get("packages"), list):
                raise ValueError("missing packages array")
            for item in d["packages"][:1000]:
                try:
                    results.append(candidate(item, base))
                except Exception as e:
                    errors.append({"source": url, "app": str(item.get("title", item.get("id", "?")))[:200], "reason": str(e)})
            nxt = (d.get("paging") or {}).get("nextUrl")
            if not nxt:
                break
            url = absolute(base, nxt)
    except Exception as e:
        errors.append({"source": url, "reason": str(e)})
    return results, errors

def ar_members(f):
    if f.read(8) != b"!<arch>\n":
        raise ValueError("not an ar-format IPK")
    end = f.seek(0, 2)
    f.seek(8)
    while f.tell() < end:
        hdr = f.read(60)
        if len(hdr) != 60 or hdr[58:] != b"\x60\n":
            raise ValueError("invalid ar header")
        name = hdr[:16].decode("ascii").strip().rstrip("/")
        size = int(hdr[48:58])
        pos = f.tell()
        if size < 0 or pos + size > end:
            raise ValueError("invalid ar member size")
        yield name, pos, size
        f.seek(pos + size + (size % 2))

def metadata(f, ident, ver):
    control = appinfo = None
    for name, pos, size in ar_members(f):
        if not name.startswith(("control.tar", "data.tar")):
            continue
        f.seek(pos)
        blob = f.read(size)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r|*") as t:
            total = 0
            for i, member in enumerate(t):
                total += max(0, member.size)
                if i >= 20000 or total > 600 * 1024 * 1024:
                    raise ValueError("archive expansion limit")
                if not member.isfile() or member.size > 1024 * 1024:
                    continue
                path = member.name.lstrip("./")
                if name.startswith("control.tar") and path == "control":
                    control = t.extractfile(member).read().decode("utf-8", "replace")
                if name.startswith("data.tar") and path.endswith("/" + ident + "/appinfo.json"):
                    appinfo = json.load(t.extractfile(member))
                if name.startswith("data.tar") and path == "appinfo.json":
                    appinfo = json.load(t.extractfile(member))
    if not control or not isinstance(appinfo, dict):
        raise ValueError("internal control or appinfo.json not found")
    fields = dict(line.split(": ", 1) for line in control.splitlines() if ": " in line and not line.startswith(" "))
    if fields.get("Package") != ident or appinfo.get("id") != ident:
        raise ValueError("internal package ID mismatch")
    if fields.get("Version") != ver or appinfo.get("version") != ver:
        raise ValueError("internal version mismatch")
    arch = fields.get("Architecture", "").lower()
    if arch not in {"all", "arm", "armv7", "armv7l", "armhf", "armv7a", "noarch"}:
        raise ValueError("unsupported or unknown package architecture: " + arch)
    return arch

def permanent_release_url(m):
    """Resolve a temporary GitHub asset through public release metadata."""
    url = m["ipkUrl"]
    u = urlsplit(url)
    if u.hostname not in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}:
        return url
    match = re.fullmatch(r"/github-production-release-asset/(\d+)/([^/]+)", u.path)
    if not match:
        raise ValueError("temporary release URL has no recoverable repository/filename")
    repo_id, filename = match.group(1), unquote(match.group(2))
    expected = "sha256:" + digest(m)
    found = set()
    fallback = set()
    # Public REST endpoint. Never send credentials to upstream download hosts.
    for page in range(1, 4):
        releases, _ = read_json("https://api.github.com/repositories/" + repo_id + "/releases?per_page=100&page=" + str(page))
        if not isinstance(releases, list):
            raise ValueError("invalid GitHub releases API response")
        for release in releases:
            if release.get("draft") or release.get("prerelease"):
                continue
            tag = release.get("tag_name", "")
            for asset in release.get("assets", []):
                if asset.get("name") != filename:
                    continue
                stable = asset.get("browser_download_url", "")
                if urlsplit(stable).hostname != "github.com" or "/releases/download/" not in urlsplit(stable).path:
                    continue
                if EXPERIMENTAL.search(unquote(stable)):
                    continue
                safe(stable)
                sha = asset.get("digest")
                if sha:
                    if sha.lower() == expected:
                        found.add(stable)
                elif tag.lstrip("vV") == m["version"]:
                    fallback.add(stable)
        if found or len(releases) < 100:
            break
    choices = found or fallback
    if len(choices) != 1:
        raise ValueError("permanent release URL not uniquely matched to manifest")
    return choices.pop()

def verify(p):
    m = p["manifest"]
    m["ipkUrl"] = permanent_release_url(m)
    h = hashlib.sha256()
    n = 0
    with tempfile.TemporaryFile() as f, fetch(m["ipkUrl"]) as r:
        while True:
            block = r.read(65536)
            if not block:
                break
            n += len(block)
            if n > MAX_IPK:
                raise ValueError("package exceeds download limit")
            h.update(block)
            f.write(block)
        if h.hexdigest() != digest(m):
            raise ValueError("SHA-256 mismatch")
        if m.get("ipkSize") is not None and m["ipkSize"] != n:
            raise ValueError("declared size mismatch")
        f.seek(0)
        arch = metadata(f, m["id"], m["version"])
    return {"bytes": n, "architecture": arch, "sha256": h.hexdigest()}

def catalog(packages):
    n = len(packages)
    return {"paging": {"page": 1, "count": n, "maxPage": 1, "itemsTotal": n, "prevUrl": None, "nextUrl": None}, "packages": sorted(packages, key=lambda p: p["title"].casefold())}

def write(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def main():
    base = json.loads((BASE / "apps.json").read_text())
    sources = json.loads((BASE / "sources.json").read_text())
    old = {p["id"]: p for p in base["packages"]}
    hashes = {digest(p["manifest"]): p["id"] for p in old.values()}
    report = {"existing": len(old), "sources": len(sources), "feed_errors": [], "verified": [], "rejected": [], "existing_flags": []}
    for p in old.values():
        if EXPERIMENTAL.search(unquote(p["manifest"]["ipkUrl"])) or p["id"] in BLOCK_IDS:
            report["existing_flags"].append({"id": p["id"], "title": p["title"], "reason": "existing experimental or restricted entry; retained pending review"})
    proposals = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for found, errors in pool.map(scan_source, sources):
            report["feed_errors"].extend(errors)
            for p in found:
                m = p["manifest"]
                ident = p["id"]
                if ident in old:
                    previous = old[ident]["manifest"]
                    if version(m["version"]) <= version(previous["version"]):
                        continue
                    if not previous.get("sourceUrl") or m.get("sourceUrl", "").rstrip("/") != previous["sourceUrl"].rstrip("/"):
                        report["rejected"].append({"id": ident, "reason": "update source changed"})
                        continue
                if digest(m) in hashes and hashes[digest(m)] != ident:
                    continue
                group = proposals.setdefault(ident, {})
                group[(m["version"], digest(m))] = p
    verified = []
    def one(entry):
        ident, group = entry
        errors = []
        for p in sorted(group.values(), key=lambda p: version(p["manifest"]["version"]), reverse=True):
            try:
                return p, verify(p), errors
            except Exception as e:
                errors.append({"id": ident, "version": p["manifest"]["version"], "reason": str(e)})
        return None, None, errors
    with ThreadPoolExecutor(max_workers=3) as pool:
        for p, details, errors in pool.map(one, proposals.items()):
            report["rejected"].extend(errors)
            if p:
                h = details["sha256"]
                if h in hashes and hashes[h] != p["id"]:
                    continue
                hashes[h] = p["id"]
                verified.append(p)
                report["verified"].append({"id": p["id"], "title": p["title"], "version": p["manifest"]["version"], "kind": "update" if p["id"] in old else "new", **details})
    merged = dict(old)
    merged.update({p["id"]: p for p in verified})
    OUT.mkdir(exist_ok=True)
    write(OUT / "report.json", report)
    write(OUT / "candidates.json", catalog(verified))
    write(OUT / "proposed-apps.json", catalog(merged.values()))
    pending = [p for ident, group in proposals.items()
               if not any(v["id"] == ident for v in verified)
               for p in group.values()]
    write(OUT / "pending-downloads.json", {"status": "UNVERIFIED_DO_NOT_PUBLISH",
          "packages": pending})
    print("Unverified candidate versions:", len(pending))
    print("Existing:", len(old), "| Sources:", len(sources), "| Verified proposals:", len(verified), "| Proposed total:", len(merged))
    print("Runtime on TV not tested. Production apps.json unchanged.")
if __name__ == "__main__":
    main()
