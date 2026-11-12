#!/usr/bin/env python3
"""FortiSIEM Report Studio — 命令列產生器。

Access Key／Client Secret 只從環境變數 FORTISIEM_CLIENT_SECRET（或互動式 getpass）讀取，
絕不會作為命令列參數（避免出現在 ps），也不會寫入磁碟。

    export FORTISIEM_CLIENT_SECRET='...'
    python3 generate.py --host 10.1.2.3 --client-id <your-client-id> \\
        --kind siem --version 1.5 --theme light --lang zh --days 7

    python3 generate.py --kind siem --version 1.5 --theme light --lang zh --from-data
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

STUDIO = Path(__file__).resolve().parent
ENGINE = STUDIO / "engine"
TOOL = ENGINE / "tool"
V15 = ENGINE / "v15"
WORK = STUDIO / "work"
OUT = STUDIO / "out"
PY = sys.executable

if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))
from studio_lib import (  # noqa: E402
    HKT,
    badge_ot,
    calendar_span_days,
    date_tag_from_meta,
    en_day_phrase,
    now_hkt,
    parse_hkt,
    redact,
    sanitize_json_meta,
    scrub_text,
    zh_day_phrase,
)


def log(msg: str) -> None:
    now = now_hkt().strftime("%H:%M:%S")
    print(f"[{now} HKT] {redact(msg)}", flush=True)


def default_days(kind: str) -> float:
    return 3.0 if kind == "ot" else 7.0


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="generate.py",
        description="由 FortiSIEM MCP（唯讀）產生單檔離線 HTML 安全報告。Access Key 只經環境變數或隱藏提示輸入。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "例子:\n"
            "  export FORTISIEM_CLIENT_SECRET='...'\n"
            "  python3 generate.py --host https://<supervisor-ip> --client-id <your-client-id> "
            "--kind siem --version 1.5 --theme light --lang zh --days 7\n"
            "  python3 generate.py --kind ot --version 1.5 --theme dark --lang zh --days 3 --from-data\n"
            "  python3 generate.py --kind siem --version 1.3 --theme dark --lang zh --from-data\n"
            "\n"
            "時間視窗用香港時間。只填日期時代表當日 00:00；結束時間為不含上界。\n"
            "若要包含 11 月 11 日全日，結束請填 2026-11-12 或 2026-11-11 23:59。\n"
            "預設結束為現在。\n"
        ),
    )
    p.add_argument("--host", default=os.environ.get("FORTISIEM_HOST") or None,
                   help="Supervisor IP 或主機（可帶 https://）。即時收集時必填。")
    p.add_argument("--client-id", default=os.environ.get("FORTISIEM_CLIENT_ID") or None,
                   help="FortiSIEM MCP OAuth client id。即時收集時必填。")
    p.add_argument("--kind", choices=("siem", "ot"), default="siem", help="報告種類：siem 或 ot（預設 siem）")
    p.add_argument("--version", dest="fmt", choices=("1.5", "1.3"), default="1.5",
                   help="格式版本：1.5（預設）或 1.3（僅 SIEM 經典 cyber HUD，深色）")
    p.add_argument("--theme", choices=("light", "dark"), default="light", help="主題：light 或 dark")
    p.add_argument("--lang", choices=("zh", "en"), default="zh", help="報告語言：zh（繁中，預設）或 en")
    p.add_argument("--days", type=float, default=None, help="回看日數（SIEM 預設 7，OT 預設 3）")
    p.add_argument("--start", help="視窗開始，HKT（YYYY-MM-DD 或 'YYYY-MM-DD HH:MM'）")
    p.add_argument("--end", help="視窗結束，HKT（預設現在；日期為當日 00:00，不含上界）")
    p.add_argument("--from-data", action="store_true", help="唔再查 FortiSIEM，用 work/ 內上次收集到嘅 JSON 重建")
    p.add_argument("--out-dir", type=Path, default=None, help="報告輸出目錄（預設 out/）")
    p.add_argument("--workers", type=int, default=2, help="全量收集 MCP session 數（OAuth 400 可改 1）")
    p.add_argument("--timeout", type=int, default=120, help="每條查詢逾時秒數")
    p.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=True,
                   help="略過 TLS 憑證驗證（預設開啟，適用自簽證書；--no-insecure 則驗證）")
    # Deliberately no --secret / --client-secret.
    return p.parse_args(argv)


def resolve_window(args) -> tuple:
    kind = args.kind
    end = parse_hkt(args.end) if args.end else now_hkt()
    if args.start:
        start = parse_hkt(args.start)
        if start >= end:
            raise SystemExit("--start 必須早於 --end")
        days = calendar_span_days(start, end)
        relative = False
    else:
        days = float(args.days) if args.days is not None else default_days(kind)
        start = end - __import__("datetime").timedelta(days=days)
        relative = True
    return start, end, days, relative


def prepare_dirs(out_dir: Path) -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "v15").mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)


def base_env(args, start, end, days, relative) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ENGINE), str(V15), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    env["FORTISIEM_ENGINE_DIR"] = str(ENGINE)
    env["FORTISIEM_REPORT_ROOT"] = str(WORK)
    env["FORTISIEM_REPORT_DAYS"] = f"{days:g}"
    env["FORTISIEM_SPAN_ZH"] = zh_day_phrase(days)
    env["FORTISIEM_SPAN_EN"] = en_day_phrase(days)
    env["FORTISIEM_BADGE"] = badge_ot(days)
    env["FORTISIEM_THEME"] = args.theme
    env["FORTISIEM_LANG"] = args.lang
    env["FORTISIEM_VERIFY_TLS"] = "0" if args.insecure else "1"
    if args.host:
        env["FORTISIEM_HOST"] = args.host
    if args.client_id:
        env["FORTISIEM_CLIENT_ID"] = args.client_id
    if not relative:
        env["FORTISIEM_WINDOW_START"] = start.strftime("%Y-%m-%d %H:%M:%S")
        env["FORTISIEM_WINDOW_END"] = end.strftime("%Y-%m-%d %H:%M:%S")
    else:
        env.pop("FORTISIEM_WINDOW_START", None)
        env.pop("FORTISIEM_WINDOW_END", None)
    return env


def run(cmd: list[str], env: dict, cwd: Path | None = None) -> None:
    display = [c if len(c) < 200 else c[:80] + "…" for c in cmd]
    log("$ " + " ".join(display))
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd or STUDIO),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(redact(line.rstrip("\n")), flush=True)
    rc = proc.wait()
    if rc != 0:
        raise SystemExit(f"指令失敗（結束碼 {rc}）：{' '.join(display)}")


def need_secret(args) -> None:
    if args.from_data:
        return
    if os.environ.get("FORTISIEM_CLIENT_SECRET"):
        return
    if not sys.stdin.isatty():
        raise SystemExit(
            "未設定 FORTISIEM_CLIENT_SECRET。請先：\n"
            "  export FORTISIEM_CLIENT_SECRET='…'\n"
            "或者用 --from-data 由已有 JSON 重建。"
        )
    os.environ["FORTISIEM_CLIENT_SECRET"] = getpass.getpass("FortiSIEM API Access Key / Client Secret: ")


def need_live_creds(args) -> None:
    if args.from_data:
        return
    if not args.host:
        raise SystemExit("請提供 --host（Supervisor IP 或主機）。即時收集沒有內建預設值。")
    if not args.client_id:
        raise SystemExit("請提供 --client-id（FortiSIEM MCP OAuth client id）。即時收集沒有內建預設值。")


def day_stem(kind: str, days: float, fmt: str) -> str:
    n = f"{int(days)}" if float(days).is_integer() else f"{days:g}"
    if kind == "ot":
        return f"fortisiem-ot-iot-{n}day-report-v{fmt}"
    return f"fortisiem-{n}day-report-v{fmt}"


def finalize(html_path: Path, out_dir: Path, filename: str, host: str | None) -> Path:
    text = html_path.read_text(encoding="utf-8")
    secret = os.environ.get("FORTISIEM_CLIENT_SECRET") or ""
    if secret and len(secret) > 8 and secret in text:
        raise SystemExit("拒絕寫出報告：內容似乎含有 Access Key，已中止以免洩漏。")
    text = text.replace(
        "<dt>Supervisor</dt><dd>${esc(M.supervisor)}</dd>",
        "<dt>查詢範圍</dt><dd>FortiSIEM MCP</dd>",
    )
    text = text.replace(
        "<dt>Supervisor</dt><dd>${esc(M.supervisor||"")}</dd>",
        "<dt>查詢範圍</dt><dd>FortiSIEM MCP</dd>",
    )
    text = scrub_text(text, host=host)
    dest = out_dir / filename
    dest.write_text(text, encoding="utf-8")
    # never leave secret in the file we just wrote
    check = dest.read_text(encoding="utf-8")
    if secret and len(secret) > 8 and secret in check:
        dest.unlink(missing_ok=True)
        raise SystemExit("拒絕寫出報告：輸出檢查到 Access Key，檔案已刪除。")
    log(f"完成：{dest}  （{dest.stat().st_size:,} bytes）")
    print(f"RESULT {dest}", flush=True)
    return dest


def last_siem_json() -> tuple[Path, Path]:
    pulse = WORK / "fsm-v15-7d-data.json"
    full = WORK / "fsm-v15-7d-full-data.json"
    return pulse, full


def last_ot_json() -> Path:
    preferred = WORK / "ot-collect.json"
    if preferred.is_file():
        return preferred
    cands = sorted(WORK.glob("ot*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if cands:
        return cands[0]
    return preferred


def collect_siem(args, env, days, relative, start, end) -> tuple[Path, Path]:
    pulse, full = last_siem_json()
    env = env.copy()
    env["FORTISIEM_PULSE_JSON"] = str(pulse)
    env["FORTISIEM_FULL_JSON"] = str(full)

    log(f"1/4 收集 pulse（{'近 ' + f'{days:g}' + ' 日' if relative else start.strftime('%Y-%m-%d %H:%M') + ' 至 ' + end.strftime('%Y-%m-%d %H:%M') + ' HKT'}）…")
    run([PY, str(ENGINE / "collect_v15_7d.py")], env)

    log("2/4 收集完整數據…")
    fsm = [
        PY, str(TOOL / "fsm_report.py"),
        "--data-only",
        "--data-out", str(full),
        "--workers", str(args.workers),
        "--timeout", str(args.timeout),
        "--theme", "v1.3",
        "--lang", args.lang,
    ]
    if args.host:
        fsm += ["--host", args.host]
    if args.client_id:
        fsm += ["--client-id", args.client_id]
    if args.insecure:
        fsm.append("--insecure")
    else:
        fsm.append("--no-insecure")
    if relative:
        fsm += ["--days", f"{days:g}"]
    else:
        fsm += ["--start", start.strftime("%Y-%m-%d %H:%M"), "--end", end.strftime("%Y-%m-%d %H:%M")]
    try:
        run(fsm, env)
    except SystemExit:
        if args.workers != 1:
            log("全量收集失敗，改用 --workers 1 重試…")
            for i, x in enumerate(fsm):
                if x == "--workers":
                    fsm[i + 1] = "1"
            run(fsm, env)
        else:
            raise
    return pulse, full


def build_siem_v15(args, env, pulse: Path, full: Path, days: float, out_dir: Path) -> Path:
    sanitize_json_meta(pulse)
    sanitize_json_meta(full)
    env = env.copy()
    env["FORTISIEM_PULSE_JSON"] = str(pulse)
    env["FORTISIEM_FULL_JSON"] = str(full)

    log("3/4 砌 v1.3 base HTML…")
    base = WORK / "v15" / "_base_v13_7day.html"
    base.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            PY, str(TOOL / "fsm_report.py"),
            "--from-data", str(full),
            "--theme", "v1.3",
            "--lang", "zh",  # v1.5 shell starts from ZH; EN overlay applied later
            "--out", str(base),
        ],
        env,
    )

    log("4/4 套 v1.5 格式（攻擊流程 + 主題）…")
    dark_out = WORK / "fortisiem-7day-report-v1.5.html"
    env["FORTISIEM_BASE_HTML"] = str(base)
    env["FORTISIEM_SIEM_DARK_OUT"] = str(dark_out)
    run([PY, str(V15 / "build_v15_7d.py")], env)

    variant = WORK / f"fortisiem-v15-{args.lang}-{args.theme}.html"
    env["FORTISIEM_VARIANT_OUT"] = str(variant)
    run([PY, str(V15 / "build_v15_7d_variants.py")], env)

    tag = date_tag_from_meta(full, pulse)
    name = f"{day_stem('siem', days, '1.5')}-{args.lang}-{args.theme}-{tag}.html"
    return finalize(variant, out_dir, name, args.host)


def build_siem_v13(args, env, full: Path, days: float, out_dir: Path) -> Path:
    sanitize_json_meta(full)
    log("砌經典 v1.3（cyber HUD，深色）…")
    tmp = WORK / f"fortisiem-v13-{args.lang}.html"
    run(
        [
            PY, str(TOOL / "fsm_report.py"),
            "--from-data", str(full),
            "--theme", "v1.3",
            "--lang", args.lang,
            "--out", str(tmp),
        ],
        env,
    )
    tag = date_tag_from_meta(full)
    name = f"{day_stem('siem', days, '1.3')}-{args.lang}-dark-{tag}.html"
    return finalize(tmp, out_dir, name, args.host)


def collect_ot(args, env) -> Path:
    dest = WORK / "ot-collect.json"
    env = env.copy()
    env["FORTISIEM_OT_JSON"] = str(dest)
    log("收集 OT/IoT 數據（token-safe 比對，唔會用標題 ILIKE '%OT%' 充數）…")
    run([PY, str(ENGINE / "collect_ot.py")], env)
    return dest


def build_ot_v15(args, env, collect: Path, days: float, out_dir: Path) -> Path:
    sanitize_json_meta(collect)
    log("砌 OT v1.5 報告…")
    tmp = WORK / f"fortisiem-ot-v15-{args.lang}-{args.theme}.html"
    env = env.copy()
    env["FORTISIEM_OT_JSON"] = str(collect)
    env["FORTISIEM_OT_OUT"] = str(tmp)
    env["FORTISIEM_HKCI_JSON"] = str(ENGINE / "assets" / "ot-5d-embed-v13.json")
    # Prefer a freshly generated SIEM v1.3 base if present, else the shipped one
    gen_base = WORK / "v15" / "_base_v13_7day.html"
    shipped = V15 / "_base_v13_7day.html"
    env["FORTISIEM_BASE_HTML"] = str(gen_base if gen_base.is_file() else shipped)
    run([PY, str(V15 / "build_ot15_3d.py")], env)
    tag = date_tag_from_meta(collect)
    name = f"{day_stem('ot', days, '1.5')}-{args.lang}-{args.theme}-{tag}.html"
    return finalize(tmp, out_dir, name, args.host)


def validate_combo(args) -> None:
    if args.kind == "ot" and args.fmt == "1.3":
        raise SystemExit("OT/IoT 報告只支援格式 v1.5。經典 v1.3 僅適用於 SIEM。")
    if args.fmt == "1.3" and args.theme == "light":
        raise SystemExit("經典 v1.3 只有深色 cyber HUD 主題。請改用 --theme dark，或改選 v1.5。")


def main(argv=None) -> int:
    args = parse_args(argv)
    validate_combo(args)
    need_live_creds(args)
    need_secret(args)

    start, end, days, relative = resolve_window(args)
    out_dir = (args.out_dir or OUT).expanduser().resolve()
    prepare_dirs(out_dir)
    env = base_env(args, start, end, days, relative)

    span = zh_day_phrase(days)
    log(
        f"開始產生：kind={args.kind}  version={args.fmt}  theme={args.theme}  lang={args.lang}  "
        f"視窗={start.strftime('%Y-%m-%d %H:%M')} → {end.strftime('%Y-%m-%d %H:%M')} HKT（{span}）"
        + ("  [--from-data]" if args.from_data else "")
    )

    if args.kind == "siem":
        pulse, full = last_siem_json()
        if args.from_data:
            if not pulse.is_file() or not full.is_file():
                raise SystemExit(f"--from-data 需要已有 {pulse} 同 {full}")
            log(f"跳過收集，用現有數據：{pulse.name} / {full.name}")
        else:
            pulse, full = collect_siem(args, env, days, relative, start, end)
        if args.fmt == "1.3":
            build_siem_v13(args, env, full, days, out_dir)
        else:
            build_siem_v15(args, env, pulse, full, days, out_dir)
    else:
        collect = last_ot_json()
        if args.from_data:
            if not collect.is_file():
                raise SystemExit(f"--from-data 需要已有 {WORK / 'ot-collect.json'}（或 work/ 內其他 ot*.json）")
            log(f"跳過收集，用現有數據：{collect}")
        else:
            collect = collect_ot(args, env)
        build_ot_v15(args, env, collect, days, out_dir)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit("已中斷")
