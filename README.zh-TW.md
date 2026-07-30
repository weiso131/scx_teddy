# scx_teddy

一個基於 eBPF（sched_ext）的實驗性排程器與**框架**，用來研究 per-task 排程。它在
線收集每個任務的執行行為、用 ML 模型（K-means）對任務分群，並對每個 cluster 套用一
套排程策略 —— 優先權、時間片，以及在大小核（big.LITTLE）機器上的核種放置。

設計目標是讓人*容易收集資料、也容易改排程策略*：對自己的 workload 訓練一個模型、寫
一份小小的 JSON 策略，就能跑 —— 不必重新編譯。整套流程有 Streamlit GUI 包起來
（見 [`gui/`](gui/README.md)）。

## 系統需求

- 支援 sched_ext 的 Linux 核心
- Root 權限（eBPF）
- Rust 工具鏈、libbpf
- Python 3 + `numpy`、`pandas`、`scikit-learn`（訓練 + GUI）

## 編譯

```bash
cargo build --release
pip install -r requirements.txt
```

## 兩種模式

scx_teddy 有兩種模式：**collect**（收集任務資料成 CSV）與 **classify**（套用訓練好
的模型即時排程任務）。

### 步驟 1：收集任務資料

```bash
sudo ./target/release/scx_teddy -m collect -c 60 -o event.csv
```

**選項：**
- `-m, --mode <MODE>` — `collect` 或 `classify`（預設：`collect`）
- `-c, --collect-duration <SECONDS>` — 收集間隔（預設：600）
- `-o, --output <PATH>` — 輸出 CSV（預設：`event.csv`）
- `--min-events <N>` — 任務被納入的最小事件數（預設：2）
- `--csv-checkpoint` — 每個 cycle 都寫 CSV。預設只在關閉時寫一次（存記憶體）；開啟
  後每 cycle checkpoint，崩潰 / `kill -9` 才不會丟資料。
- `--max-runtime <SECONDS>` — 跑這麼久後停止（寫出 CSV 並退出）。`0` = 無限制
  （預設：`0`）。
- `-v, --verbose` — 詳細 log 寫到 `teddy.log`

### 步驟 2：訓練 K-means 模型

```bash
python3 train.py event.csv -o model.json
```

要只用特定 workload 訓練，傳 `--train-config` 檔，一行一個 `comm` 前綴（`#` 開頭與
空行忽略）：

```bash
python3 train.py event.csv -o model.json --train-config train_config.config
```

這會用 elbow 法自動選 cluster 數（或 `-k` 指定）、把模型（centroids + scaler）寫成
JSON，並寫 `<model>_result.json`（每個 cluster 的成員：tid、tgid、ppid、command）。

**選項：**
- `-o, --output <PATH>` — 輸出模型 JSON（預設：`model.json`）
- `-k, --clusters <N>` — cluster 數（省略則自動）
- `--train-config <PATH>` — comm 前綴過濾清單（預設：全部任務）
- `--filter-tid / --filter-tgid / --filter-cmd <…>` — 過濾訓練集
- `--exclude-feature <NAME…>` — 排除這些 feature 欄位再訓練

訓練結束會印一組針對 feature 本身的診斷——近乎常數與二元的欄位、feature 之間的
等級相關、有效維度、不同 cluster 數的 silhouette，以及分群偏離名稱分群的程度。
要照診斷結果調整，就排掉某欄重訓：

```bash
python3 train.py event.csv -o model.json --exclude-feature iowait_ratio avg_sleep_ms
```

排除欄位會改變模型的 feature 清單，但這樣訓出的模型跟其他模型吃一樣的 CSV——
scx_teddy 從 model JSON 讀 feature 名稱，只取用列出的那些。名稱打錯會直接報錯，
不會被忽略。

### 步驟 3：寫排程策略

`config.json` 把每個 cluster id 對到一個排程條目，外加一個 `default` 條目（給沒列到
的 cluster、以及 scx_teddy 放不進去的任務）：

```json
{
  "clusters": {
    "0": { "prio": 0,  "slice_mode": "fixed",    "slice_ns": 1500000, "cpu_kind": 1, "cpu_prefer": 1 },
    "1": { "prio": 2,  "slice_mode": "fixed",    "slice_ns": 3000000 },
    "6": { "prio": 11, "slice_mode": "adaptive", "slice_sigma": 1.0,  "cpu_prefer": 2 }
  },
  "default": { "prio": 11, "slice_mode": "fixed", "slice_ns": 100000 }
}
```

- **prio** — 優先權階層，`0` = 最高、`11` = 最低（共 12 階）。dispatch 從 `prio 0`
  往下。`prio < 4` 視為 *critical*：這些任務在喚醒時會主動找 idle CPU（延遲最低）；
  `prio >= 4` 只是 enqueue 排隊。
- **slice_mode** — `fixed`（`slice_ns`，下限 100000）或 `adaptive`（`slice_sigma`：
  時間片隨任務平均執行時間與其變異度縮放）。
- **cpu_kind** *(大小核機器)* — `0`（預設）= 共用，任何核種都可跑；否則 1-based，
  `1` = 最快核種（P-core），數字越大越慢（E-core / tier-N）。scx_teddy 啟動時從
  cpufreq 偵測核種並印出有效範圍。
- **cpu_prefer** — `select_cpu` 的速度傾向：`0` = 無（依 `cpu_kind` 自動推導）、
  `1` = 傾向最快、`2` = 傾向最慢。

### 步驟 4：以分類模式執行

```bash
sudo ./target/release/scx_teddy -m classify -c 1 --model model.json --config config.json
```

**classify 選項：**
- `--model <PATH>` / `--config <PATH>` — 訓練好的模型 + 策略（兩者必填）
- `-c, --collect-duration <SECONDS>` — 重新分類週期（預設：600；GUI 用 1s 才即時）
- `--target-model <PATH>` / `--target-config <PATH>` — 給特化目標家族的*第二套*模型
  + 策略（選用，見下）
- `--control-interval <SECONDS>` — 多久重讀一次 control 檔（預設：5）

## 特化：優化單一 process 家族

scx_teddy 可以給某個 process 與其所有後代一套自己的排程，跟系統其餘任務區隔開 ——
例如優先化某遊戲的執行緒。目標家族是在 scx_teddy *外部*決定的：把單一值寫進
`/tmp/scx_teddy/` 下的 control 檔，scx_teddy 每 `--control-interval` 秒重讀：

- `control_ppid` — 目標 ppid（`0` = 無）
- `control_model` / `control_config` — 只套用在目標家族的模型 + 策略（空 = 目標家族
  也用 default 策略）

任何能寫檔的程式都能驅動它。`target_finder_helper/` 附了一個範例 scanner，會偵測正
在執行的 Steam 遊戲並發布它的 ppid；協議與如何自己寫一個見
[`target_finder_helper/README.md`](target_finder_helper/README.md)。

## GUI

[`gui/`](gui/README.md) 是包住整套流程的 Streamlit dashboard：Collect、Train、
t-SNE 視覺化、Classify（含即時 config 編輯器 + target 選擇）、htop 風格的 Overall
總覽。詳見 [`gui/README.md`](gui/README.md)。

---

[English](README.md)
