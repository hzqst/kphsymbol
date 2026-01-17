# 代码结构

- **根目录脚本**：
  - `download_symbols.py`：按 `kphdyn.xml` 下载 PE 与 PDB。
  - `update_symbols.py`：解析 PDB，更新/同步 `kphdyn.xml` 中字段偏移，支持 `syncfile` 等模式。
  - `reverse_symbols.py`：对缺 PDB 的 PE 用 IDA + LLM 生成符号映射。
  - `upload_server.py`：HTTP 上传服务，验证 PE/签名并按符号目录结构落盘。
  - `migrate_symboldir.py`：符号目录迁移/整理脚本。
- **主要目录**：
  - `symbols/`：下载或上传的符号与 PE 文件目录（按 arch/version/hash 组织）。
  - `output/`：脚本输出文件。
  - `uploads/`：HTTP 服务上传临时目录。
  - `ida/`：与 IDA 相关的脚本/资源。
  - `.serena/`, `.claude/`：工具配置目录。
