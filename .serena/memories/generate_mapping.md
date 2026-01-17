# ida/generate_mapping.py 概述
`ida/generate_mapping.py` 是 **符号映射生成器**，通过对比两个 Windows 内核版本的反汇编/伪代码输出，调用 LLM 推断 `sub_xxx/loc_xxx` 与真实符号的映射关系，并将结果追加到目标 PE 同目录的 `SymbolMapping.yaml`。

# 职责
- 从命令行和环境变量解析 IDA 路径与 LLM API 配置。
- 调用 `ida/ida.py`（disasm 模式）生成 reference/reverse 的 YAML 反汇编输出。
- 加载/格式化模板（`ida/GenerateMapping.md`）并构造提示词。
- 调用 OpenAI/Anthropic API 获取映射结果并解析。
- 追加结果到 `SymbolMapping.yaml`（去重）。

# 架构
- **配置与参数**：
  - `parse_args()`：解析 `-func/-reference/-reverse/-ida/-provider/-api_base/-api_key/-model/-debug/-template`。
  - `get_ida_path()`：`-ida` > `IDA64_PATH` > `PATH`。
  - `get_api_config()`：`-api_key/-api_base` > 环境变量（`OPENAI_API_KEY/OPENAI_API_BASE` 或 `ANTHROPIC_API_KEY/ANTHROPIC_API_BASE`）。
- **资源定位与校验**：
  - `check_pdb_exists()`：检查 reference PE 同目录下是否存在 `ntkrnlmp.pdb/ntoskrnl.pdb/ntkrla57.pdb`。
  - `get_yaml_path()`：输出 YAML 命名为 `<func_name>.yaml`。
- **反汇编生成**：
  - `run_ida_disasm()`：拼接 `ida64.exe -A -P -S"ida.py --func <FuncName>" <pe>`，运行后检查 YAML 产物。
- **提示词构建**：
  - `load_prompt_template()`：默认读取 `ida/GenerateMapping.md`。
  - `format_prompt()`：支持 `{reference.xxx}` / `{reverse.xxx}` 占位符；`xrefs` 特殊格式化。
- **LLM 调用**：
  - `call_llm_for_mapping()`：根据 provider 分发。
  - `_call_openai()` / `_call_anthropic()`：构建客户端并发起请求。
- **响应解析与持久化**：
  - `parse_llm_response()`：提取 ```yaml``` 块并 `yaml.safe_load`。
  - `append_to_symbol_mapping()`：去重追加并写回 `SymbolMapping.yaml`。

# 核心实现与工作流
## 总流程
1. `main()` 解析参数 -> 打印配置。
2. 加载模板 `GenerateMapping.md`（可用 `-template` 替换）。
3. 校验 reference/reverse PE 存在。
4. `check_pdb_exists(reference_pe)` 确保 reference 版本具备 PDB。
5. `get_ida_path()` 获取 `ida64.exe` 路径。
6. `get_api_config()` 获取 API key/base。
7. 对 reference/reverse：
   - 若 `<func>.yaml` 已存在则复用，否则 `run_ida_disasm()` 调用 `ida/ida.py` 生成。
8. `load_yaml_data()` 读取 YAML。
9. `extract_unmapped_symbols()` 从 `procedure` 与 `disasm_code` 中提取 `sub_/loc_` 集合；为空则退出。
10. `format_prompt()` 生成 prompt -> `call_llm_for_mapping()` 调用 LLM。
11. `parse_llm_response()` 解析 YAML 映射。
12. `append_to_symbol_mapping()` 追加到 reverse PE 目录的 `SymbolMapping.yaml`，输出统计。

# 依赖
- **标准库**：`argparse`, `os`, `re`, `shutil`, `subprocess`, `sys`。
- **第三方**：`pyyaml`；`openai`（可选）、`anthropic`（可选）。
- **外部工具**：IDA Pro (`ida64.exe`)；`ida/ida.py` 脚本；reference PE 对应的 PDB 文件。
- **模板文件**：默认 `ida/GenerateMapping.md`（也可自定义）。

# 注意事项
- `openai/anthropic` 模块未安装会直接退出；需提前 `pip install openai` / `pip install anthropic`。
- `run_ida_disasm()` 有 10 分钟超时，超时或未生成 YAML 直接 `sys.exit(1)`。
- 模板占位符仅支持 `{reference.xxx}` / `{reverse.xxx}`，字段缺失会替换为空字符串。
- `extract_unmapped_symbols()` 只匹配 `sub_`/`loc_` + 十六进制；其它命名不会被视为“未映射”。
- `append_to_symbol_mapping()` 仅对 key 去重，不校验 value 是否变化。
- 依赖 reference 版本具备 PDB，否则流程直接终止。
- 生成/复用 YAML 的路径固定为 PE 同目录下 `<func>.yaml`，注意同名函数会覆盖/复用。

# 关联关系
- 调用 `ida/ida.py` 的 `disasm` 模式生成 YAML 反汇编/伪代码数据。
- 模板默认读取 `ida/GenerateMapping.md`（或 `GenerateMappingDisasmOnly.md` 作为备选参考模板）。
- 生成的 `SymbolMapping.yaml` 可被 `ida/ida.py --mode symbol_remap` 用于批量重命名。