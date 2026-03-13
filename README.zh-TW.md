# scx_teddy

一個基於 eBPF 的實驗性排程器，能夠在線收集任務執行資料並傳遞給使用者空間。這為未來使用 ML 模型或 agent 進行排程優化提供了基礎。

## 建置

```bash
cargo build --release
```

## 使用方式

```bash
sudo ./target/release/scx_teddy [選項]
```

**選項：**
- `-v, --verbose` - 啟用詳細輸出
- `-c, --collect-duration <秒數>` - 資料收集間隔（秒），預設為 600

**範例：**

```bash
# 每 60 秒收集並報告統計資料
sudo ./target/release/scx_teddy -c 60
```

每個時間間隔後，排程器會印出每個 TID 的事件數量，並重置計數器以進行下一輪收集。

## 系統需求

- 支援 sched_ext 的 Linux 核心
- Root 權限（eBPF 操作所需）
- Rust 工具鏈
- libbpf

---

[English Documentation](README.md)
