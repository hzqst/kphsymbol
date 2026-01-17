# update_symbols.py 概述
`update_symbols.py` 是 **kphdyn.xml 符号偏移更新器**。它以 YAML 配置为驱动，借助 `llvm-pdbutil` 解析 PDB，更新 XML 中的字段偏移；并提供 `-syncfile`（同步符号文件到 XML）、`-fixnull`（基于 SymbolMapping.yaml 修复空字段）、`-fixstruct`（从最接近版本拷贝 struct_offset 回填）三种辅助模式。

# 职责
- 解析命令行参数与运行模式。
- 读取 YAML 配置（目标文件列表与符号定义），校验符号格式与类型。
- 解析 XML 并维护 `<data>`/`<fields>` 结构，分配/复用 fields id。
- 调用 `llvm-pdbutil` 解析 PDB，提取结构成员/全局变量/函数偏移。
- 在不同模式下更新 XML：正常更新、同步新增条目、修复 null、修复 fallback struct。

# 架构
- **配置层**：
  - `parse_args()`：处理 `-xml/-symboldir/-yaml/-debug/-sha256/-pdbutil/-outxml/-syncfile/-fast/-fixnull/-fixstruct`。
  - `HAS_YAML` / `HAS_PEFILE`：按需依赖检测。
- **YAML 解析与校验**：
  - `load_yaml_config()`：读取 `file` 与 `symbols` 列表，校验 `name`、`type` 与 `struct_offset/var_offset/fn_offset` 的唯一性。
  - `parse_symbol()` / `parse_symbol_with_fallback()`：解析 `STRUCT->Member` 与多候选备用字段。
- **PDB 解析层（llvm-pdbutil）**：
  - `run_llvm_pdbutil()`：`dump -types` 用于结构成员解析。
  - `run_llvm_pdbutil_publics()`：`dump -publics` 用于全局/函数符号解析。
  - `run_llvm_pdbutil_sections()` + `parse_section_headers()`：解析段信息以辅助计算偏移。
  - `parse_llvm_pdbutil_output()` + `find_member_*()`：解析成员偏移，支持嵌套成员（`u1.State`）与 bitfield。
  - `parse_public_symbol_offset()`：从 publics/sections 解析符号偏移。
  - `parse_pdb_all_symbols()`：汇总所有符号偏移，支持 `struct_offset/var_offset/fn_offset`，并处理 `bits` 输出。
- **XML 操作层**：
  - `collect_existing_fields()` / `find_matching_fields_id()` / `allocate_new_fields_id()` / `create_fields_element()`：复用或创建 `<fields>`。
  - `collect_all_referenced_ids()` / `remove_orphan_fields()`：清理孤立 fields。
  - `save_xml_with_header()`：保持固定 XML 头与顺序输出。
- **模式流程层**：
  - `syncfile_main()`：从符号目录增量补齐 `<data>`。
  - `fixnull_main()`：对 fields id=0 的条目使用 `SymbolMapping.yaml` 修复。
  - `fixstruct_main()`：对 struct_offset fallback 值进行版本回填。
  - `main()`：入口调度与结果输出。

# 核心实现与工作流
## 正常模式（更新 XML 偏移）
1. `main()` 解析参数并校验 XML/符号目录。
2. `load_yaml_config()` 读取 YAML 配置（目标文件列表与符号定义）。
3. 解析 XML：`collect_existing_fields()`、`get_all_entries_for_files()`。
4. 逐条 `<data>` 处理：
   - 通过 `get_pdb_path()` 定位 `ntkrnlmp.pdb`。
   - `parse_pdb_all_symbols()` 调用 `llvm-pdbutil` 解析 offsets（支持 struct/var/fn 与 bitfield）。
   - `find_matching_fields_id()` 复用已有 fields；否则 `allocate_new_fields_id()` 新建。
   - 将 fields id 写回 `<data>`。
5. `create_fields_element()` 添加新 fields；`remove_orphan_fields()` 清理无引用 fields。
6. `save_xml_with_header()` 输出到 `-outxml`（默认覆盖输入）。

## syncfile 模式
- `scan_symbol_directory()` 遍历 `{symboldir}/{arch}/{file}.{version}/{sha256}/{file}`。
- `parse_file_path_info()` 解析 `arch/file/version/sha256`；`find_data_entry()` 检查 XML 是否存在。
- 对缺失条目：`parse_pe_info()`（`pefile`）提取 `timestamp/size`，并校验 SHA256；
  `find_insert_position()` 找到插入位置；`create_data_entry()` 新增 `<data>`（fields id=0）。
- 最后保存 XML 并输出统计。

## fixnull 模式
- `get_null_entries_for_files()` 选出 fields id=0 的条目。
- 读取 `SymbolMapping.yaml`：`get_symbol_mapping_path()` + `load_symbol_mapping()` + `parse_symbols_from_mapping()`。
- **var_offset/fn_offset**：通过 `symbol_addr - ImageBase` 计算偏移。
- **struct_offset**：仍需 PDB；若缺失则写入 fallback 值（`0xffff` / `0xffffffff`）。
- 完成后保存 XML。

## fixstruct 模式
- `get_entries_needing_struct_fix()` 识别包含 fallback struct_offset 的条目。
- `find_closest_valid_entry()` 基于 `version_distance()` 在同架构内选最接近的有效版本。
- 复制 struct_offset 并重建/复用 fields id，最后保存 XML。

# 依赖
- **标准库**：`os`, `re`, `argparse`, `subprocess`, `sys`, `hashlib`, `xml.etree.ElementTree`。
- **第三方**：`pyyaml`（YAML 配置）；`pefile`（syncfile）；
- **外部工具**：`llvm-pdbutil`（`dump -types/-publics/-section-headers`）。
- **输入文件**：`kphdyn.xml`、YAML 配置（如 `kphdyn.yaml`）、符号目录中的 PDB/PE。
- **辅助文件**：`SymbolMapping.yaml`（fixnull 依赖）。

# 注意事项
- 非 `-syncfile` 模式必须提供 `-yaml`；缺少 `pyyaml` 会直接退出。
- `-syncfile` 依赖 `pefile`，缺失则退出；`-fast` 会跳过已存在条目的 PE 解析。
- PDB 路径固定为 `ntoskrnl.exe.<version>/<sha256>/ntkrnlmp.pdb`，若不存在会跳过或报错。
- `parse_symbol_with_fallback()` 支持逗号分隔的备用结构成员；成员为嵌套字段时按 `u1.State` 解析。
- bitfield 输出由 `bits: true` 控制，按位输出 `(byte_offset*8 + bit_offset)`。
- `fixnull` 中 var/fn 偏移依赖 `SymbolMapping.yaml` 的 ImageBase；缺失将导致无法计算。
- `remove_orphan_fields()` 会扫描全部 `<data>`，可能删除未被引用的 `<fields>`。
- 默认覆盖输入 XML（`-outxml` 可改写）；请注意版本管理。

# 关联关系
- 依赖符号目录结构与 `SymbolMapping.yaml`，常与 `reverse_symbols.py` / `ida/generate_mapping.py` 产物联动。
- `llvm-pdbutil` 是核心解析工具，决定 struct/var/fn 偏移获取能力。
