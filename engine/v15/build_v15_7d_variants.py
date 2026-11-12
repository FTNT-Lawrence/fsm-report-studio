#!/usr/bin/env python3
"""Build FortiSIEM SIEM report v1.5 locale × theme variants.

Reuses apply_light / inject_tail / scrub_lawrence from build_v15_variants.py.
Does NOT call that module's main() (it would retarget the 5-day files).

Env:
  FORTISIEM_REPORT_ROOT, FORTISIEM_ENGINE_DIR
  FORTISIEM_SIEM_DARK_OUT  (source ZH-dark produced by build_v15_7d.py)
  FORTISIEM_VARIANT_OUT    (optional single output path)
  FORTISIEM_LANG           zh | en
  FORTISIEM_THEME          light | dark
  FORTISIEM_SPAN_ZH, FORTISIEM_SPAN_EN, FORTISIEM_REPORT_DAYS
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone, timedelta

ENGINE = pathlib.Path(os.environ.get('FORTISIEM_ENGINE_DIR') or pathlib.Path(__file__).resolve().parents[1])
ROOT = pathlib.Path(os.environ.get('FORTISIEM_REPORT_ROOT') or ENGINE)
V15 = ENGINE / 'v15'
SRC = pathlib.Path(os.environ.get('FORTISIEM_SIEM_DARK_OUT') or (ROOT / 'fortisiem-7day-report-v1.5.html'))
HKT = timezone(timedelta(hours=8))

sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(V15))
import build_v15_variants as v  # noqa: E402
from studio_lib import zh_day_phrase, en_day_phrase, date_tag_from_meta  # noqa: E402


def resolve_date_tag() -> str:
    return date_tag_from_meta(
        ROOT / 'fsm-v15-7d-full-data.json',
        ROOT / 'fsm-v15-7d-data.json',
        fallback=datetime.now(HKT).strftime('%Y%m%d'),
    )


def resolve_span() -> tuple[str, str, float]:
    days = float(os.environ.get('FORTISIEM_REPORT_DAYS') or '7')
    try:
        full = json.loads((ROOT / 'fsm-v15-7d-full-data.json').read_text(encoding='utf-8'))
        days = float((full.get('meta') or {}).get('days') or days)
    except Exception:
        pass
    span_zh = (os.environ.get('FORTISIEM_SPAN_ZH') or '').strip() or zh_day_phrase(days)
    span_en = (os.environ.get('FORTISIEM_SPAN_EN') or '').strip() or en_day_phrase(days)
    return span_zh, span_en, days


def titles(locale: str, theme: str, span_zh: str, span_en: str) -> tuple[str, str]:
    theme_label = 'Light' if theme == 'light' else 'Dark'
    # ZH dark historically omitted "· Dark"; keep Light suffix, add Dark only for light? Task examples:
    # 「FortiSIEM 七日安全報告 · v1.5 · Light」
    # Dark ZH: 「FortiSIEM 七日安全報告 · v1.5」 (original) — we add nothing for dark ZH
    if locale == 'zh':
        lang = 'zh-HK'
        title = f'FortiSIEM {span_zh}安全報告 · v1.5'
        if theme == 'light':
            title += ' · Light'
        return lang, title
    lang = 'en'
    title = f'FortiSIEM {span_en} Security Report · v1.5'
    if theme == 'light':
        title += ' · Light'
    return lang, title


def set_lang_title(html: str, locale: str, theme: str, span_zh: str, span_en: str) -> str:
    lang, title = titles(locale, theme, span_zh, span_en)
    html = re.sub(r'<html\b([^>]*)lang="[^"]*"', f'<html\\1lang="{lang}"', html, count=1)
    if f'lang="{lang}"' not in html[:200]:
        html = re.sub(r'<html\b', f'<html lang="{lang}"', html, count=1)
    html = re.sub(r'<title>[^<]*</title>', f'<title>{title}</title>', html, count=1)
    return html


def patch_overlay_for_nday(html: str, span_zh: str, span_en: str, days: float) -> str:
    """Ensure runtime EN map covers N-day chrome (overlay still ships 五日 keys)."""
    needle = "'五日安全報告':'5-Day Security Report'"
    last_n = f"Last {int(days) if float(days).is_integer() else days:g} days"
    in_n = f"In {int(days) if float(days).is_integer() else days:g} days"
    extra = (
        "'五日安全報告':'5-Day Security Report',"
        "'七日安全報告':'7-Day Security Report',"
        f"'{span_zh}安全報告':'{span_en} Security Report',"
        f"'{span_zh} · v1.5':'{span_en} · v1.5',"
        f"'近{span_zh}':'{last_n}',"
        f"'{span_zh}內':'{in_n}'"
    )
    if needle in html:
        # replace first occurrence only if our span key is not already next to it
        if f"'{span_zh}安全報告'" not in html.split('const MAP', 1)[-1][:2000] if 'const MAP' in html else html:
            html = html.replace(needle, extra, 1)
        elif f"'{span_zh}安全報告'" not in html:
            html = html.replace(needle, extra, 1)
    elif f"'{span_zh}安全報告'" not in html:
        # inject before 安全報告 generic key if present
        generic = "'安全報告':'Security Report'"
        if generic in html:
            html = html.replace(generic, extra + "," + generic, 1)
    return html


def inject_tail_nd(html: str, locale: str, theme: str, span_zh: str, span_en: str, days: float) -> str:
    html = v.inject_tail(html, locale, theme)
    return patch_overlay_for_nday(html, span_zh, span_en, days)


def build_variant(src_html: str, locale: str, theme: str, span_zh: str, span_en: str, days: float) -> str:
    html = v.strip_variants(src_html)
    html = set_lang_title(html, locale, theme, span_zh, span_en)
    if theme == 'light':
        html = v.apply_light(html)
    html = v.scrub_lawrence(html)
    html = inject_tail_nd(html, locale, theme, span_zh, span_en, days)
    _, title = titles(locale, theme, span_zh, span_en)
    html = re.sub(r'<title>[^<]*</title>', f'<title>{title}</title>', html, count=1)
    html = v.scrub_lawrence(html)
    html = html.replace('165.84.173.36', '')
    host = (os.environ.get('FORTISIEM_HOST') or '').strip()
    if host:
        bare = re.sub(r'^https?://', '', host, flags=re.I).split('/')[0]
        if bare:
            html = html.replace(bare, '')
        html = html.replace(host, '')
        html = html.replace('https:///', 'https://')
    html = re.sub(r',?\s*"supervisor"\s*:\s*"[^"]*"', '', html)
    html = re.sub(r',?\s*"audience"\s*:\s*"[^"]*"', '', html)
    return html


def smoke(path: pathlib.Path, locale: str, theme: str, span_zh: str, span_en: str) -> None:
    t = path.read_text(encoding='utf-8')
    lang, title = titles(locale, theme, span_zh, span_en)
    got = re.search(r'<title>([^<]+)</title>', t)
    assert got and got.group(1) == title, got.group(1) if got else 'no title'
    assert f'lang="{lang}"' in t[:400]
    assert 'window.__V15__' in t
    assert 'LAWRENCE LAU' not in t
    assert '為 LAWRENCE' not in t
    assert '165.84.173.36' not in t
    if theme == 'light':
        assert 'theme-light' in t
        assert "#e8eef5" in t or "'#e8eef5'" in t
        assert "backgroundColor:'rgba(255,255,255,.97)'" in t
        assert "textStyle:{color:'#0E1216'" in t
        cut = t.find('const TT=')
        if cut > 0:
            app = t[cut:]
            assert "inRange:{color:['#e8eef5'" in app or "splitArea:{areaStyle:{color:['#e8eef5','#f0f4f8']}}" in app
            assert "color:['#0c1218','#090d12']" not in app
            assert "inRange:{color:['#0b1a22'" not in app
    size = path.stat().st_size
    assert size > 400_000, f'too small: {size}'
    print(f'OK {path.name}  {size:,} bytes  {locale}/{theme} title={title}')


def main() -> int:
    if not SRC.exists():
        raise SystemExit(f'missing source {SRC}')
    span_zh, span_en, days = resolve_span()
    locale = (os.environ.get('FORTISIEM_LANG') or 'zh').strip().lower()
    theme = (os.environ.get('FORTISIEM_THEME') or 'light').strip().lower()
    if locale not in ('zh', 'en'):
        raise SystemExit(f'unsupported lang {locale}')
    if theme not in ('light', 'dark'):
        raise SystemExit(f'unsupported theme {theme}')

    src = SRC.read_text(encoding='utf-8')
    print(f'Source {SRC} size={SRC.stat().st_size:,}  span={span_zh}/{span_en}  {locale}/{theme}')

    html = build_variant(src, locale, theme, span_zh, span_en, days)
    out = os.environ.get('FORTISIEM_VARIANT_OUT')
    tag = resolve_date_tag()
    if out:
        dest = pathlib.Path(out)
    else:
        dest = ROOT / f'fortisiem-report-v1.5-{locale}-{theme}-{tag}.html'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(html, encoding='utf-8')
    smoke(dest, locale, theme, span_zh, span_en)
    md5 = hashlib.md5(dest.read_bytes()).hexdigest()
    print(f'WROTE {dest}  size={dest.stat().st_size}  md5={md5}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
