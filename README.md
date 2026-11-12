# FortiSIEM Report Studio

本機工具：用網頁填 Supervisor 位址同 API Access Key，揀報告版本同顏色，然後由 Python 產生一份**單檔、離線可開**嘅 FortiSIEM 安全報告（圖表同字型已內嵌）。

查詢經 FortiSIEM MCP（OAuth2 `client_credentials`）。程式**只讀**：只會呼叫 `query_*`／`get_*` 類工具；`update_*`、`clear_*`、`append_* comment` 一律拒絕。

## 你需要

- Python **3.9 或以上**（Windows / macOS / Linux）
- 安裝依賴（目前只有 `requests`，供 pulse／OT 收集使用；其餘係標準庫）：

```bash
cd fsm-report-studio
python3 -m pip install -r requirements.txt
```

- FortiSIEM Supervisor 可達（即時收集時），以及 MCP 的 **OAuth Client ID** 同 **Client Secret／API Access Key**
- Supervisor 常用自簽證書：預設會略過 TLS 驗證。若要驗證，網頁取消預設行為並勾選「驗證 TLS」，或 CLI 加 `--no-insecure`

## 用網頁產生（建議）

```bash
cd fsm-report-studio
python3 start.py
```

程式會喺 **127.0.0.1** 揀一個空閒連接埠（先試 8765），並嘗試打開瀏覽器。只監聽本機，不會綁 `0.0.0.0`。

然後：

1. 填 **Supervisor IP／主機**（必填；沒有預設值）
2. 填 **OAuth Client ID**（FortiSIEM MCP 的 OAuth client id，必填）
3. 填 **API Access Key／Client Secret**（密碼欄；除非用已儲存 JSON 重建，否則必填）
4. 揀報告種類、格式版本、顏色、語言同時間視窗
5. 撳 **「產生報告」**，睇進度日誌；完成後可下載 HTML，檔案亦會寫入 `out/`

可選：勾選「記住 IP 同 Client ID（不會記住 Access Key）」——只存到瀏覽器 `localStorage`，**永遠不會記住 Access Key**。Access Key 亦不會寫入 cookie、日誌、數據 JSON 或報告。

同一時間只會產生一份報告。

## 用命令列（可跳過瀏覽器）

**不要**把 Secret 寫成命令列參數（會出現在 `ps`）。只從環境變數或隱藏提示讀取：

```bash
export FORTISIEM_CLIENT_SECRET='...'
python3 generate.py --host 10.1.2.3 --client-id <your-client-id> \
  --kind siem --version 1.5 --theme light --lang zh --days 7
```

其他例子：

```bash
# OT／IoT，最近 3 日，深色
python3 generate.py --host https://<supervisor-ip> --client-id <your-client-id> \
  --kind ot --version 1.5 --theme dark --lang zh --days 3

# 指定香港時間視窗（結束預設為現在；只填日期代表當日 00:00，結束為不含上界）
python3 generate.py --host <supervisor-ip> --client-id <your-client-id> \
  --kind ot --version 1.5 --theme light --lang zh \
  --start 2026-11-09 --end 2026-11-12

# 用上次收集到嘅 JSON 重建（唔使 Secret）
python3 generate.py --kind siem --version 1.5 --theme light --lang zh --from-data

# SIEM 經典 v1.3（只有深色 cyber HUD）
python3 generate.py --kind siem --version 1.3 --theme dark --lang zh --from-data
```

`python3 generate.py --help` 可睇完整參數。

若終端機可用而尚未設定 `FORTISIEM_CLIENT_SECRET`，程式會用 `getpass` 隱藏提示你輸入。

## 支援嘅報告組合

| 種類 | 版本 | 主題 | 語言 | 預設視窗 |
|---|---|---|---|---|
| SIEM 安全報告 | **v1.5** | 淺色／深色 | 繁中；英文為對照表覆蓋 | 最近 7 日 |
| OT／IoT 安全報告 | **v1.5** | 淺色／深色（淺色為主要校對版本） | 繁中；英文為對照表覆蓋 | 最近 3 日 |
| SIEM 經典 | **v1.3** | 僅深色 cyber HUD | 繁中／英文（工具內建） | 最近 7 日 |

標題會跟視窗日數調整，例如「FortiSIEM 七日安全報告 · v1.5 · Light」、「FortiSIEM 三日 OT 安全報告 · v1.5 · Light」。英文版透過現有對照表喺瀏覽器改寫介面字句，**部分內文可能仍係中文**。

時間視窗：最近 N 日，或絕對 `--start`／`--end`（香港時間，`YYYY-MM-DD` 或 `YYYY-MM-DD HH:MM`）。預設結束為現在。只填日期時代表該日 00:00；結束為不含上界。若要包含某日全日，結束請填翌日或該日 `23:59`。

## 輸出位置

完成嘅報告在 `out/`，例如：

- `out/fortisiem-7day-report-v1.5-zh-light-YYYYMMDD.html`
- `out/fortisiem-ot-iot-3day-report-v1.5-zh-light-YYYYMMDD.html`

中途檔案在 `work/`，可隨時刪除。下次若勾選「用上次收集嘅 JSON 重建」，會讀 `work/` 裡的數據。

報告係單檔 HTML，不寫入 Supervisor IP，亦不會出現「為 LAWRENCE」之類個人歸屬。

## Access Key 同安全

- 網頁把 Access Key **POST 一次到本機伺服器記憶體**，再經子行程環境變數交給產生器
- **不會**寫入磁碟、日誌、`localStorage`、cookie、數據 JSON 或 HTML 報告
- 命令列不接受 `--secret` 參數
- 進度日誌會遮蔽 secret／Bearer token
- 伺服器只綁 `127.0.0.1`

## 疑難排解

**HTTP 401／OAuth 失敗**  
檢查 Supervisor 位址、Client ID 同 Access Key 是否配對。Token 端點為 `https://<host>/phoenix/rest/pub/security/oauth/token`。

**OAuth HTTP 400（尤其係連接成功後再失敗）**  
多 session 同時換 token 時，部分 Supervisor 會 400。把 `--workers` 改為 `1`（`generate.py --workers 1`）。網頁目前預設 2，若失敗可改用命令列指定 1 再跑。

**連線逾時**  
加大 `--timeout`（預設 120 秒）。確認本機到 Supervisor 的 443 可達。

**未設定 Secret**  
即時收集必須有 `FORTISIEM_CLIENT_SECRET`，或在網頁密碼欄填寫。重建已儲存數據則可不用。

**自簽證書錯誤**  
預設已略過驗證。若你開了「驗證 TLS」或 `--no-insecure` 而證書不受信任，會失敗——改回略過驗證，或提供系統信任的 CA。

**--from-data 提示找不到 JSON**  
先成功即時收集一次，確認 `work/fsm-v15-7d-data.json` 同 `work/fsm-v15-7d-full-data.json`（SIEM），或 `work/ot-collect.json`（OT）存在。

**Python 模組 `requests` 缺失**  
執行 `python3 -m pip install -r requirements.txt`。

## 目錄結構

```
fsm-report-studio/
├── start.py          # 本機網頁
├── generate.py       # 命令列產生器
├── requirements.txt
├── README.md
├── web/              # 控制台頁面
├── engine/           # 收集同排版引擎（唯讀 MCP）
├── work/             # 中途數據
└── out/              # 完成嘅 HTML 報告
```
