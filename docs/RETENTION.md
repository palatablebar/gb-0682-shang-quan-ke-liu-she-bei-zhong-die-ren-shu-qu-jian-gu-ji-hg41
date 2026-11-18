# 留存期与可核验证据裁决

## 裁决结论

| 材料 | 留存期 | 存放位置 | 到期处理 |
|---|---|---|---|
| 原始 CSV 整表字节、`source_b64`、被丢弃行字段值 | 7 天 | 运行态 SQLite（`runs.body`） | `purge_raw` 删除整表字段，只留结论与行号 |
| 正式区间证据包（sealed pack） | 365 天 | 证据库 `EVIDENCE_VAULT_PATH`（默认 `data/vault`） | 到期按 `evidence_expires_at` 另行处置 |
| 隔离行原值 | 随原始表 7 天 | 运行态 | 删除；证据包只留行号/ID/原因码/叶哈希 |

核心原则：**交上下界，但审计必须能问清“采用了哪些观测、版本如何取舍、交集依据是什么”。**
因此证据包保留能复核区间的最小材料，而不是整表——既满足 7 天清理，又保证一年内可独立复核。

## 证据包内容（`app/modules/m7_archive/evidence.py`）

每个封存批次一份 JSON，`pack_hash` 为对全包规范化内容的 SHA-256：

1. **封存清单**：`schema_version`、规则版本、参数、封存时间、来源文件 SHA-256、留存策略；
2. **整表 Merkle 锚点**：对全部物理数据行（含列数不齐、被版本取代、同版冲突等隔离行及完全重复行；空行与重复表头按对账单独计数）建叶，只留存根哈希与叶数，不留整表；每条采纳观测与每条隔离行都附带可独立验证的包含证明；
3. **正式区间**（`intervals[]`）：
   - `official_interval` 封存值与 `recomputed_interval` 重算值必须相等；
   - `intersection_basis`：逐步交集推导（`max/min` 各项、三方交集 T 的上下界项、联合公式）；
   - `adopted_observations[]`：被采纳观测的归一化字段、叶哈希、Merkle 包含证明；
4. **版本取舍**（`version_decisions[]`）：每个观测键的全部候选行，只记行号/ID/版本/叶哈希/选中标记/原因码
   （`SELECTED` / `VERSION_SUPERSEDED` / `CONFLICT`），被取代行的字段值不进包；
5. **隔离摘要**（`quarantine_summary[]`）：行号/ID/原因码/叶哈希/Merkle 包含证明，`raw_retained=false`，原值不进包；
6. **对账与业务汇总**、**前包哈希**（哈希链）。

## 清理后如何复核（`verify_pack`）

仅凭证据包即可，不需要原始整表：

1. 重算 `pack_hash`，与封存值比对；
2. 对每个区间用 `intersection_basis` 重新执行同一估界公式，结果必须等于正式区间；
3. 对每条采纳观测验证 Merkle 包含证明，确认其叶承诺隶属于整表根；
4. 模型中每个区域/两两交集/三方交集数值都能反查到具体采纳观测；
5. 版本取舍的选中行必须出现在采纳观测中，未采纳原因码合规；
6. 对账平衡、Merkle 叶数与台账行数一致；
7. 哈希链 `prev_pack_hash` 逐包衔接，断链可被 `registry.chain_intact` 发现。

任何区间、叶哈希或自哈希被篡改，复核均失败（见 `tests/test_evidence_retention.py::test_tampered_pack_is_detected`）。

## 幂等与原子切换（`app/modules/m7_archive/vault.py`）

- **同批重跑不重复生成**：以 `run_id` 去重，已封存则原样返回既有包，`created=false`，证据文件不重写；
- **内容寻址 + 文件锁**：包写在 `packs/<run_id>.json`，封存全程持 `flock` 互斥；
- **先落盘后切换登记**：包经临时文件 + `os.replace` 原子写入并通过自检，才更新 `registry.json`；
- **切换失败回滚**：登记写入失败时删除新包、保留旧登记，并写 `switch.log`，上一版档案始终可核验；
- **哈希链更新失败不毁证据**：链与登记分离，链异常只记日志，包本身仍可独立复核。

证据库布局：

```
data/vault/
  registry.json      # 封存登记（含原始/证据到期时间、清理标记）
  chain.json         # 哈希链
  switch.log         # 切换/回滚/清理审计日志
  packs/<run_id>.json
```

## 页面与导出同一份材料

- 归档页 `/m7_archive` 直接渲染证据库中的封存包；未封存时才显示运行态预览并明确标注；
- 导出 `/api/archive/<run_id>/export.csv` 只从封存包生成（`sealed_bundle`），未封存返回 409；
- 因此页面所见与导出文件、以及 `/api/archive/<run_id>/pack`、`/verify` 指向同一份 `pack_hash` 材料。

## API

| 方法与路径 | 作用 |
|---|---|
| `POST /api/runs` | 跑批；对账平衡即自动幂等封存 |
| `POST /api/archive/<run_id>/seal` | 手动封存（对账未平拒绝） |
| `GET  /api/archive/<run_id>/pack` | 取封存证据包原文 |
| `GET  /api/archive/<run_id>/verify` | 独立复核结论与逐项 findings |
| `GET  /api/archive/registry` | 封存登记与哈希链完整性 |
| `GET  /api/archive/<run_id>/export.csv` | 由封存包导出 CSV（唯一正式导出入口） |
| `POST /api/archive/<run_id>/purge-raw` | 模拟 7 天清理：删运行态整表并登记 |
