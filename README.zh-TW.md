# scx_teddy

## 概述

scx_teddy 是一個基於 sched-ext 的實驗性排程器，提供追蹤工具來分析並記錄多執行緒任務的執行特性。透過分析收集到的執行資料，結合對工作負載特性的理解，可以手動或藉助 LLM 來精細調整排程參數，以優化特定應用程式的效能。

## 組件

### 1. scx_teddy - 主排程器

載入並執行基於 BPF 的排程策略的主要排程器組件。

#### 建置

```bash
cd scx_teddy
cargo build --release
```

#### 使用方式

```bash
sudo ./target/release/scx_teddy --config <配置檔路徑>
```

**選項：**
- `-c, --config <配置檔路徑>` - JSON 配置檔路徑（必需）
- `-v, --verbose` - 啟用詳細輸出

#### 配置檔格式

排程器使用 JSON 配置檔來指定排程參數：

```json
{
  "target_mode": 0,
  "tgid": 12345,
  "tasks": [
    {
      "tid": 28182,
      "prio": 2,
      "slice": 100000000000,
      "on_ecore": 1
    }
  ]
}
```

**配置欄位：**
- `target_mode`（必需）：排程器的目標模式
- `tgid`（可選）：執行緒群組 ID。如果指定，會設定 `target_single_tgid`
- `tasks`（必需）：任務配置陣列
  - `tid`：執行緒 ID
  - `prio`：優先權等級（有效範圍：0-2）
  - `slice`：時間片段，單位為奈秒（nanoseconds）
  - `on_ecore`：是否在 E-core 上執行（1）或否（0）

**範例配置檔：**
- `config.example.json` - 不含 TGID 的基本配置
- `config.with-tgid.example.json` - 包含 TGID 的配置

### 2. Tracer - 任務執行時間與睡眠追蹤器

基於 eBPF 的工具，用於監控任務執行時間、睡眠時長和排程行為。

#### 建置

```bash
cd tracer
cargo build --release
```

#### 使用方式

```bash
sudo ./target/release/tracer [選項]
```

**選項：**
- `-m, --mode <模式>` - 追蹤模式（預設：tid）
  - `tid`：追蹤特定執行緒（Thread ID）
  - `tgid`：追蹤整個程序（Process ID）
- `-t, --target <目標>` - 指定追蹤目標（可多次使用）
  - 如果未指定：
    - `tid` 模式：追蹤當前執行緒
    - `tgid` 模式：追蹤當前程序
- `-d, --duration <時長>` - 追蹤時長（秒），預設為 10
  - 設為 0 表示無限期追蹤（直到按 Ctrl+C）

#### 使用範例

1. **追蹤特定 TID 10 秒**
   ```bash
   sudo ./tracer -m tid -t 12345
   ```

2. **追蹤特定 TGID（整個程序）30 秒**
   ```bash
   sudo ./tracer -m tgid -t 5678 -d 30
   ```

3. **追蹤多個 TID**
   ```bash
   sudo ./tracer -m tid -t 100 -t 200 -t 300 -d 60
   ```

4. **無限期追蹤當前執行緒**
   ```bash
   sudo ./tracer -m tid -d 0
   ```

5. **追蹤多個 TGID**
   ```bash
   sudo ./tracer -m tgid -t 1000 -t 2000 -d 20
   ```

#### 輸出統計資訊

追蹤器提供全面的統計資訊，包括：

- **Event count**：捕獲的事件總數
- **Runtime**：執行時間統計
  - Average：平均執行時間
  - Std dev：標準差
  - Min/Max：最小值和最大值
- **Sleep Duration**：睡眠時間統計（如果有睡眠事件）
  - Count：睡眠事件數量
  - Average, Std dev, Min, Max
- **Sleep Interval**：連續睡眠之間的時間
  - Count, Average, Std dev, Min, Max

所有時間值以毫秒（ms）為單位報告。

## 系統需求

- 支援 sched_ext 的 Linux 核心
- Root 權限（eBPF 操作所需）
- Rust 工具鏈
- libbpf


## 最近更新

- 實作使用者端目標指定功能，支援 JSON 配置
- 新增任務執行時間與睡眠行為監控追蹤器
- 實作基於 eBPF 的排程框架

---

[English Documentation](README.md)
