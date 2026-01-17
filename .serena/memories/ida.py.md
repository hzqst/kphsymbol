# ida/ida.py 概述
`ida/ida.py` 是用于 **IDA Pro 自动化分析** 的脚本入口，支持三种模式：
- `disasm`：按函数名或特征码生成反汇编（可选 F5 伪代码）。
- `xref`：导出函数/变量的交叉引用信息。
- `symbol_remap`：应用 `SymbolMapping.yaml`，将 `sub_*/loc_*` 等未映射符号批量重命名，并写入 ImageBase。

# 职责
- 解析 `-S` 脚本参数（基于 `idc.ARGV`）。
- 等待 IDA 自动分析完成，保证后续 API 可用。
- 在三种模式间进行调度，并输出 YAML 结果。
- 在 symbol_remap 模式下更新 YAML 并执行重命名。

# 架构
- **参数解析层**：`parse_script_args()` 统一解析 `--mode/--func/--var/--signature/--disasm_lines/--no_procedure/--no_qexit`。
- **分析/检索层**：
  - 地址解析：`get_function_address()` 先 `ida_name.get_name_ea`，失败则遍历 `idautils.Functions()`。
  - 特征码：`search_signature()` 将字符串拆成 data+mask，使用 `ida_bytes.find_bytes` 搜索。
  - 反汇编：`get_function_disassembly()` 从函数头生成汇编；`get_disassembly_from_address()` 从特征码地址起步。
  - XREF：`get_xrefs()` 用 `idautils.XrefsTo` 收集引用并格式化。
- **格式化层**：`format_address()`、`format_xref_address()` 负责地址/符号文本输出；`get_export_ordinal()` 为导出函数添加序号注释。
- **导出层**：
  - `export_function_info()` 输出 YAML，字段包含 `virtualaddress/disasm_code` 和可选 `procedure`（F5 伪代码）；自定义 Dumper 让多行字符串使用 `|`。
  - `export_xref_info()` 输出 `virtualaddress/xrefs`。
- **工作流控制**：`main()` 统一入口；`safe_qexit()` 依据 `--no_qexit` 决定是否退出 IDA。

# 核心实现与工作流
## 启动与通用流程
1. `main()` -> `parse_script_args()` 获取模式与参数。
2. 记录 `--no_qexit`，调用 `wait_auto()` 等待自动分析结束。
3. 获取 `input_file = idc.get_input_file_path()`。
4. 按 `mode` 分支执行：`symbol_remap` / `disasm` / `xref`。

## disasm 模式
- 入口：`--mode disasm --func <FuncName>`；可选 `--signature` / `--disasm_lines` / `--no_procedure`。
- 搜索路径：
  - 若传 `--signature`：`search_signature()` 找首个匹配地址。
  - 否则：`get_function_address()` 按函数名定位。
- 反汇编：
  - signature 模式用 `get_disassembly_from_address()`（从匹配地址起步，按行数截断）。
  - 函数名模式用 `get_function_disassembly()`（包含导出序号注释、类型签名、public/proc 头、endp 尾）。
- 伪代码：默认尝试 `get_function_pseudocode()`（Hex-Rays 可选），`--no_procedure` 可跳过。
- 导出：`export_function_info()`，输出路径默认 `build_output_path()`（IDB 所在目录 + `<FuncName>.yaml`）。

## xref 模式
- 入口：`--mode xref --func <FuncName>` 或 `--mode xref --var <VarName>`。
- 定位：函数用 `get_function_address()`，变量用 `ida_name.get_name_ea()`。
- 采集：`get_xrefs()` 收集 `idautils.XrefsTo`，并用 `format_xref_address()` 输出 “函数名+偏移” 或 “段:偏移”。
- 导出：`export_xref_info()` 输出 `virtualaddress/xrefs`。

## symbol_remap 模式
- 入口：`--mode symbol_remap --symbol_remap_file <path>`；不传则默认使用输入 PE 同目录 `SymbolMapping.yaml`。
- 加载：`load_symbol_mapping()` 读取 YAML：`{unmapped: mapped}`。
- ImageBase：`get_image_base()` 获取 ImageBase，写入 YAML（键为十六进制字符串，值固定 `ImageBase`）。
- 重命名：遍历映射，`ida_name.get_name_ea()` 找地址，`rename_function()` 调用 `ida_name.set_name()` 重命名。
- 结果统计：成功/失败/跳过计数并退出。

# 依赖
- **IDA Python API**：`ida_auto/ida_bytes/ida_funcs/ida_hexrays/ida_ida/ida_kernwin/ida_lines/ida_name/ida_idaapi/ida_segment/idautils/idc`。
- **Python 标准库**：`os`, `sys`。
- **第三方库**：`pyyaml`（用于 YAML 输出/读取）。
- **外部环境**：
  - IDA Pro（GUI/Headless 均可）。
  - Hex-Rays 反编译器（可选；缺失时 `procedure` 为空）。
  - 可结合 `ida/ida.cfg` 或 `-A`/`TVHEADLESS=1` 做自动化加载。

# 注意事项
- `idc.ARGV` 仅在 `-S"ida.py ..."` 场景下有值；参数解析顺序依赖 `ARGV`。
- `--no_qexit` 用于 GUI 调试；默认情况下脚本会调用 `idc.qexit()`。
- `build_output_path()` 优先用 `idc.get_idb_path()` 推导输出目录（更可靠）。
- 特征码搜索只返回首个匹配地址；若特征码不唯一需自行控制模式与输出。
- `search_signature()` 支持 `?`/`??` 通配符，但对奇数字符长度会忽略末尾字符。
- `get_function_pseudocode()` 依赖 Hex-Rays 插件初始化成功；失败会降级并继续输出反汇编。
- YAML 输出包含多行字符串，使用自定义 `LiteralDumper` 以 `|` 形式保存。
- `symbol_remap` 会修改 YAML 文件（追加 ImageBase），注意版本管理。

# 关联与调用关系
- `ida/generate_mapping.py` 会调用 `ida/ida.py` 的 `disasm` 模式生成 YAML 反汇编，用于后续 LLM 符号映射。
- `ida/ida.cfg` 提供 Headless 自动加载 IDA 的配置模板，便于批处理运行 `ida.py`。
