#!/usr/bin/env python3
"""Shared helpers for FortiSIEM Report Studio (span wording, windows, scrubbing)."""
from __future__ import annotations

import datetime as dt
import os
import re
from pathlib import Path

HKT = dt.timezone(dt.timedelta(hours=8))

_ZH_NUM = {
    1: "一", 2: "兩", 3: "三", 4: "四", 5: "五",
    6: "六", 7: "七", 8: "八", 9: "九", 10: "十",
    14: "十四", 15: "十五", 21: "二十一", 30: "三十",
}


def now_hkt() -> dt.datetime:
    return dt.datetime.now(HKT).replace(microsecond=0)


def parse_hkt(s: str | None, *, end_of_day: bool = False) -> dt.datetime | None:
    """Parse YYYY-MM-DD or YYYY-MM-DD HH:MM[_SS] as HKT.

    Date-only values are midnight (00:00) that day. When end_of_day is True
    (used only if a caller explicitly wants an inclusive calendar end), the
    date-only form becomes the next midnight. Default matches fsm_report:
    date-only is 00:00, and the window end is exclusive.
    """
    if not s:
        return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=HKT)
        except ValueError:
            pass
    try:
        d = dt.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=HKT)
    except ValueError:
        raise ValueError(f"無法解析時間「{s}」（請用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM，香港時間）") from None
    if end_of_day:
        return d + dt.timedelta(days=1)
    return d


def zh_day_phrase(days: float) -> str:
    if float(days).is_integer():
        n = int(days)
        if n in _ZH_NUM:
            return _ZH_NUM[n] + "日"
        return f"{n} 日"
    return f"{days:g} 日"


def en_day_phrase(days: float) -> str:
    if float(days).is_integer():
        n = int(days)
        return f"{n}-Day"
    return f"{days:g}-Day"


def window_days(start: dt.datetime, end: dt.datetime) -> float:
    sec = (end - start).total_seconds()
    days = sec / 86400.0
    # Snap near-integers (e.g. 2.99 calendar days shown as 3)
    if abs(days - round(days)) < 0.05:
        return float(int(round(days))) or days
    # For "last N days" ending now, keep the nominal integer if very close
    return days


def calendar_span_days(start: dt.datetime, end: dt.datetime) -> float:
    """Whole calendar days touched, at least 1. Mon 00:00 → Wed 14:00 is 3."""
    s = start.astimezone(HKT).date()
    e = end.astimezone(HKT)
    end_date = e.date() if (e.hour or e.minute or e.second) else (e - dt.timedelta(seconds=1)).date()
    n = (end_date - s).days + 1
    return float(max(1, n))


def badge_ot(days: float) -> str:
    if float(days).is_integer():
        return f"OT · {int(days)}D"
    return f"OT · {days:g}D"


def host_variants(host: str | None) -> list[str]:
    if not host:
        return []
    h = host.strip()
    out = []
    for v in (h, h.rstrip("/")):
        if v and v not in out:
            out.append(v)
        bare = re.sub(r"^https?://", "", v, flags=re.I).split("/")[0]
        if bare and bare not in out:
            out.append(bare)
    return out


def redact(text: str, extra: list[str] | None = None) -> str:
    s = "" if text is None else str(text)
    secrets = [
        os.environ.get("FORTISIEM_CLIENT_SECRET"),
        os.environ.get("FORTISIEM_PASSWORD"),
    ]
    if extra:
        secrets.extend(extra)
    for sec in secrets:
        if sec and len(str(sec)) > 4:
            s = s.replace(str(sec), "***")
    s = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1***", s)
    s = re.sub(r"(?i)(client_secret|access_token)\s*[:=]\s*[^,&\s\"']+", r"\1=***", s)
    return s


def scrub_text(text: str, host: str | None = None) -> str:
    """Strip attribution, lab IP, and the user-supplied Supervisor host."""
    for bad in (
        "LAWRENCE LAU",
        "為 LAWRENCE LAU",
        "For LAWRENCE LAU",
        "Compiled for LAWRENCE",
        "為 LAWRENCE",
        "For LAWRENCE",
    ):
        text = text.replace(bad, "")
    text = re.sub(r',?\s*"audience"\s*:\s*"[^"]*"', "", text)
    text = re.sub(r',?\s*"supervisor"\s*:\s*"[^"]*"', "", text)
    for needle in ["165.84.173.36", *host_variants(host)]:
        if needle:
            text = text.replace(needle, "")
    text = text.replace("https:///", "https://")
    text = re.sub(r"https://\s*(?=[\"'<])", "https://", text)
    return text


def sanitize_json_meta(path: Path) -> None:
    """Drop supervisor / audience from a collected JSON file before rendering."""
    if not path.is_file():
        return
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return
    new = scrub_text(raw, host=None)
    # also drop audience key if present as JSON
    if new != raw:
        path.write_text(new, encoding="utf-8")


def date_tag_from_meta(*paths: Path, fallback: str | None = None) -> str:
    for path in paths:
        if not path or not path.is_file():
            continue
        try:
            import json
            obj = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        meta = obj.get("meta") or obj.get("window") or {}
        if isinstance(obj.get("window"), dict) and not obj.get("meta"):
            meta = {**meta, **(obj.get("window") or {})}
        for field in ("end_hkt", "queried_at_hkt", "generated_hkt", "end"):
            val = ""
            if isinstance(meta, dict):
                val = str(meta.get(field) or "")
            m = re.search(r"(20\d{2})-(\d{2})-(\d{2})", val)
            if m:
                return "".join(m.groups())
        kpis = obj.get("kpis") or {}
        last = str(kpis.get("last") or "")
        m = re.search(r"(20\d{2})-(\d{2})-(\d{2})", last)
        if m:
            return "".join(m.groups())
    return fallback or now_hkt().strftime("%Y%m%d")
