# reverse_symbols.py 概述
`reverse_symbols.py` 是 **KPH 动态符号反推批处理脚本**。它扫描符号目录中缺失 PDB 的 PE 文件，选择同架构/同文件名下“低于目标版本且有 PDB”的参考版本，通过调用 `ida/ida.py` 与 `ida/generate_mapping.py` 生成符号映射，再回到 IDA 执行符号重映射，从而批量恢复符号。

# 职责
- 解析 CLI 参数与环境变量（`KPHTOOLS_SYMBOLDIR` 优先）。
- 扫描符号目录、解析路径元数据并建立版本索引。
- 为每个缺失 PDB 的目标 PE 选择最接近的参考版本（低版本且有 PDB）。
- 组织完整 workflow：IDA 反汇编 -> LLM 生成映射 -> IDA symbol_remap。
- 输出执行日志与整体统计。

# 架构
- **配置/参数层**：
  - `parse_args()`：解析 `-symboldir/-reverse/-provider/-api_key/-model/-api_base/-ida/-debug/-signature/-no_procedure/-disasm_lines/-template`；若存在 `KPHTOOLS_SYMBOLDIR` 则覆盖 `-symboldir`。
  - `get_ida_path()`：`-ida` > `IDA64_PATH` > `PATH`。
  - `get_api_config()`：`-api_key/-api_base` > 环境变量（`OPENAI_*` 或 `ANTHROPIC_*`）。
- **目录解析/索引层**：
  - `parse_version()`：将 `10.0.16299.551` 转为 `(10,0,16299,551)` 便于排序。
  - `parse_file_path_info()`：按 `{symboldir}/{arch}/{file}.{version}/{sha256}/{file}` 解析 `arch/file/version/sha256`，校验 sha256 长度与 hex 格式。
  - `scan_symbol_directory()`：遍历 `.exe/.dll/.sys`，过滤无效目录。
  - `build_pe_index()`：以 `(arch, filename)` 分组并按版本升序排序，标记 `has_pdb`（目录下任意 `.pdb`）。
  - `find_reference_pe()`：选取目标版本之前、且有 PDB 的最高版本。
- **执行层（外部工具调用）**：
  - `run_ida_disasm()`：调用 `ida/ida.py --mode disasm` 生成 `<func>.yaml`，已存在则跳过。
  - `run_generate_mapping()`：调用 `ida/generate_mapping.py` 生成 `SymbolMapping.yaml`（传递模板/模型/API 参数）。
  - `run_ida_symbol_remap()`：调用 `ida/ida.py --mode symbol_remap` 应用映射。
- **流程编排层**：`process_pe()` 组织四步流水线；`main()` 扫描与批处理并汇总结果。

# 核心实现与工作流
## 主流程
1. `main()` 解析参数并校验 `symboldir`。
2. 获取 `ida64.exe` 路径与 API 配置，打印运行参数。
3. `scan_symbol_directory()` 获取 PE 列表，`build_pe_index()` 构建索引。
4. 分离 `missing_pdb` / `with_pdb`；若无缺失直接退出。
5. 对每个缺失 PDB 的 PE：
   - `find_reference_pe()` 找最近的低版本参考。
   - `process_pe()` 执行 4 步：
     1) `run_ida_disasm()` 反汇编目标 PE
     2) `run_ida_disasm()` 反汇编参考 PE
     3) `run_generate_mapping()` 调用 LLM 生成映射
     4) `run_ida_symbol_remap()` 应用映射
6. 打印统计汇总；失败则 `exit(1)`。

## 反汇编与映射细节
- 反汇编输出文件固定为目标 PE 同目录 `"<func>.yaml"`，存在即复用。
- `-signature/-no_procedure/-disasm_lines` 透传给 `ida/ida.py` 的 disasm 模式。
- `-template` 透传给 `ida/generate_mapping.py`，用于替换默认提示词模板。

# 依赖
- **标准库**：`argparse`, `os`, `shutil`, `subprocess`, `sys`。
- **外部工具**：IDA Pro (`ida64.exe`)；`ida/ida.py`；`ida/generate_mapping.py`。
- **间接依赖**：`pyyaml`、`openai`/`anthropic`（由 `generate_mapping.py` 使用）。
- **环境变量**：`KPHTOOLS_SYMBOLDIR`、`OPENAI_API_KEY/OPENAI_API_BASE`、`ANTHROPIC_API_KEY/ANTHROPIC_API_BASE`、`IDA64_PATH`。

# 注意事项
- 目录结构必须符合 `{symboldir}/{arch}/{file}.{version}/{sha256}/{file}`，否则会被跳过。
- `check_pdb_exists()` 仅检查目录是否存在任意 `.pdb`，不验证是否匹配该 PE。
- 参考版本仅选 **低于目标版本** 且有 PDB 的最近版本；若不存在会跳过该目标。
- `run_generate_mapping()` 将 `-api_key` 作为命令行参数传递，可能在进程列表中暴露（尽管 debug 输出已做脱敏）。
- `run_ida_disasm()` / `run_ida_symbol_remap()` 默认 10 分钟超时；`run_generate_mapping()` 为 5 分钟超时。
- 输出 YAML 与 `SymbolMapping.yaml` 都位于 PE 同目录，注意多次运行的复用/覆盖行为。

# 关联关系
- 通过 `ida/ida.py` 的 `disasm`/`symbol_remap` 模式完成反汇编与重命名。
- 通过 `ida/generate_mapping.py` 调用 LLM 生成 `SymbolMapping.yaml`。
