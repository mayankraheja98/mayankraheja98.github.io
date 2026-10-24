#!/usr/bin/env python3
"""Blog helper (standard library only).
  python3 tools/post.py new "My post title"   -> creates posts/YYYY-MM-DD-my-post-title.md
  python3 tools/post.py build                 -> regenerates posts/index.json from posts/*.md
"""
import html, json, re, sys, urllib.request
import xml.etree.ElementTree as ET
from datetime import date as _date
from email.utils import parsedate_to_datetime
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent / "posts"
MEDIUM_FEED = "https://rahejahere.medium.com/feed"
MEDIUM_CACHE = DIR / "medium.json"  # last good import; used if the feed is unreachable
MEDIUM_EXCLUDE = set()              # Medium post ids (last URL segment hash) to hide, e.g. {"3942d88ce1f4"}
_NS = {"c": "http://purl.org/rss/1.0/modules/content/"}


def fetch_medium():
    """Medium RSS -> external index entries (latest ~10 posts only). Falls back to cache on failure."""
    try:
        req = urllib.request.Request(MEDIUM_FEED, headers={"User-Agent": "Mozilla/5.0 (site-build)"})
        root = ET.fromstring(urllib.request.urlopen(req, timeout=20).read())
        out = []
        for it in root.iter("item"):
            link = (it.findtext("link") or "").split("?")[0]
            pid = link.rsplit("-", 1)[-1]
            if not link.startswith("https://") or not re.fullmatch(r"[0-9a-f]+", pid) or pid in MEDIUM_EXCLUDE:
                continue
            body = it.findtext("c:encoded", "", _NS)
            text = html.unescape(re.sub(r"\s+", " ", re.sub(r"<(figure|blockquote)\b.*?</\1>|<[^>]+>", " ", body, flags=re.S))).strip()
            out.append({
                "slug": "medium-" + pid, "file": "", "url": link, "source": "medium",
                "title": it.findtext("title", "").strip(),
                "date": parsedate_to_datetime(it.findtext("pubDate")).strftime("%Y-%m-%d"),
                "tags": ["Medium"], "summary": text[:160].rsplit(" ", 1)[0] + ("…" if len(text) > 160 else ""),
                "sample": False, "words": len(text.split()),
            })
        if not out:
            raise ValueError("empty feed")
        MEDIUM_CACHE.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"medium: imported {len(out)} post(s)")
        return out
    except Exception as e:
        print(f"WARNING: medium import failed ({e}); using cache", file=sys.stderr)
        return json.loads(MEDIUM_CACHE.read_text(encoding="utf-8")) if MEDIUM_CACHE.exists() else []


def parse_front(src):
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n?(.*)$", src, re.S)
    if not m:
        return {}, src
    meta = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if not k:
            continue
        if v.startswith("[") and v.endswith("]"):
            v = [s.strip() for s in v[1:-1].split(",") if s.strip()]
        elif v == "true":
            v = True
        elif v == "false":
            v = False
        else:
            v = re.sub(r"^[\"']|[\"']$", "", v)
        meta[k] = v
    return meta, m.group(2)


def slugify(s):
    return re.sub(r"^-|-$", "", re.sub(r"[^a-z0-9]+", "-", s.lower()))


def build():
    out, seen, errors = [], set(), []
    for f in sorted(DIR.glob("*.md")):
        if f.name.lower().startswith("readme"):
            continue
        base = f.stem
        dm = re.match(r"^(\d{4}-\d{2}-\d{2})-(.+)$", base)
        slug = dm.group(2) if dm else base
        meta, body = parse_front(f.read_text(encoding="utf-8"))
        d = str(meta.get("date") or (dm.group(1) if dm else ""))
        if not re.fullmatch(r"[a-z0-9-]+", slug):
            errors.append(f"{f.name}: filename must be lowercase letters, digits and hyphens"); continue
        if not meta.get("title"):
            errors.append(f'{f.name}: missing "title" in front matter'); continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
            errors.append(f'{f.name}: missing/invalid "date" (YYYY-MM-DD)'); continue
        if slug in seen:
            errors.append(f'{f.name}: duplicate slug "{slug}"'); continue
        seen.add(slug)
        if meta.get("draft"):
            print(f"skipping draft: {f.name}"); continue
        plain = re.sub(r"[#>*`\[\]()!_-]", " ", re.sub(r"```.*?```", " ", body, flags=re.S))
        first = next((p.strip() for p in re.split(r"\n\s*\n", body)
                      if p.strip() and not re.match(r"^(#|```|>|-|\d+\.)", p.strip())), "")
        tags = meta.get("tags", [])
        out.append({
            "slug": slug, "file": f.name, "title": meta["title"], "date": d,
            "tags": tags if isinstance(tags, list) else [tags],
            "summary": meta.get("summary") or re.sub(r"\s+", " ", first)[:160],
            "sample": bool(meta.get("sample")), "words": len(plain.split()),
        })
    if errors:
        print("ERRORS:\n  " + "\n  ".join(errors), file=sys.stderr); sys.exit(1)
    out += fetch_medium()
    out.sort(key=lambda p: p["date"], reverse=True)
    (DIR / "index.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"posts/index.json updated: {len(out)} post(s)")


def create(title):
    if not title:
        print('Usage: python3 tools/post.py new "Post title"', file=sys.stderr); sys.exit(1)
    d = _date.today().isoformat()
    f = DIR / f"{d}-{slugify(title)}.md"
    if f.exists():
        print(f"Already exists: {f}", file=sys.stderr); sys.exit(1)
    f.write_text(f"---\ntitle: {title}\ndate: {d}\ntags: [DevSecOps]\nsummary: One-line teaser shown on the cards.\ndraft: true\n---\n\nWrite here in Markdown.\n\n## A heading\n", encoding="utf-8")
    print(f'Created {f.relative_to(DIR.parent)}\nRemove "draft: true" when ready, then push.')


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["build"]:
        build()
    elif args[:1] == ["new"]:
        create(" ".join(args[1:]))
    else:
        print('Usage:\n  python3 tools/post.py new "Title"\n  python3 tools/post.py build')
