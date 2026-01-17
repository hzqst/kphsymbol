# ida.py - IDA Pro 自动分析脚本
#
# 用法:
#   反汇编模式 (disasm):
#     ida64.exe -A -S"ida.py --mode disasm --func FuncName" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode disasm --signature FB488D05????????4989 --func FuncName" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode disasm --func FuncName --disasm_lines 18" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode disasm --func FuncName --no_procedure" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode disasm --func FuncName --no_qexit" "path/to/pe.exe"
#
#   通用参数:
#     --no_qexit: 任务完成/失败时不自动退出 IDA (用于 GUI 调试)
#
#   交叉引用模式 (xref):
#     ida64.exe -A -S"ida.py --mode xref --func FuncName" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode xref --var VarName" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode xref --func FuncName --output path/to/output.yaml" "path/to/pe.exe"
#
#   符号重映射模式 (symbol_remap):
#     ida64.exe -A -S"ida.py --mode symbol_remap --symbol_remap_file path/to/SymbolMapping.yaml" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode symbol_remap" "path/to/pe.exe"  # 使用 PE 同目录下的 SymbolMapping.yaml
#
# ============================================================================
# IDA 自动加载配置 (ida.cfg 或命令行参数)
# ============================================================================
# 为了让 IDA 自动以全默认方式加载 PE64 文件并自动加载 PDB，需要:
#
# 方法1: 使用命令行参数 (推荐用于 headless 模式)
#   ida64.exe -A -S"path\to\ida.py ..." "path\to\pe.exe"
#   -A: 自主模式，自动回答所有对话框
#
# 方法2: 在 %IDAUSR%\ida.cfg 或 %IDADIR%\cfg\ida.cfg 中添加:
#   OPENIDB_ONLYNEW = YES           ; 自动选择新数据库
#   ABANDON_DATABASE = YES          ; 放弃旧数据库
#   PDB_AUTOLOAD = YES              ; 自动加载 PDB
#   PDB_PROVIDER = "MSDIA140"       ; 使用 Microsoft DIA SDK
#   PDB_DOWNLOAD = YES              ; 自动从符号服务器下载 PDB
#   PE_LOAD_ANSWER = 1              ; 自动选择 PE 加载器 (1=PE64)
#
# 方法3: 环境变量
#   set TVHEADLESS=1                ; 完全无头模式
#
# 完整命令示例 (headless + 自动应答):
#   ida64.exe -A -P -S"D:\kphtools\ida\ida.py --mode disasm --func PsSetCreateProcessNotifyRoutine" "D:\kphtools\symbols\amd64\ntoskrnl.exe.10.0.22621.3668\ntoskrnl.exe"
# 完整命令示例 (GUI模式):
#   ida64.exe -P -S"D:\kphtools\ida\ida.py --mode disasm --func PsSetCreateProcessNotifyRoutine" "D:\kphtools\symbols\amd64\ntoskrnl.exe.10.0.22621.3668\ntoskrnl.exe"
#

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_name
import ida_idaapi
import ida_segment
import idautils
import idc
import os
import sys
import yaml

# 需要输出反汇编的函数名
DISASM_FUNCTION = ""

# 进行 Symbol Mapping 映射的 yaml文件
# 例如:
# sub_140822108: PspSetCreateProcessNotifyRoutine
SYMBOL_MAPPING_FILE = "SymbolMapping.yaml"

def parse_script_args():
    """
    解析 IDA 脚本参数
    IDA 通过 idc.ARGV 传递 -S 后的参数
    示例: -S"script.py --mode disasm --func FuncName"
    示例: -S"script.py --mode disasm --signature FB488D05????????4989 --func FuncName"
    示例: -S"script.py --mode xref --var VarName"
    示例: -S"script.py --mode symbol_remap --symbol_remap_file path/to/mapping.yaml"
    """
    args = {
        "mode": "disasm",
        "func": DISASM_FUNCTION,
        "var": None,  # xref 模式可用于变量
        "output": None,  # 自动生成
        "symbol_remap_file": SYMBOL_MAPPING_FILE,  # symbol_remap 模式使用的映射文件
        "signature": None,  # 特征码搜索
        "disasm_lines": None,  # 反汇编行数限制
        "no_procedure": False,  # 跳过伪代码输出
        "no_qexit": False,  # 任务完成/失败时不自动退出 IDA
    }

    argv = idc.ARGV if hasattr(idc, 'ARGV') else []

    i = 1  # 跳过脚本名
    while i < len(argv):
        if argv[i] == "--mode" and i + 1 < len(argv):
            args["mode"] = argv[i + 1]
            i += 2
        elif argv[i] == "--func" and i + 1 < len(argv):
            args["func"] = argv[i + 1]
            i += 2
        elif argv[i] == "--var" and i + 1 < len(argv):
            args["var"] = argv[i + 1]
            i += 2
        elif argv[i] == "--output" and i + 1 < len(argv):
            args["output"] = argv[i + 1]
            i += 2
        elif argv[i] == "--symbol_remap_file" and i + 1 < len(argv):
            args["symbol_remap_file"] = argv[i + 1]
            i += 2
        elif argv[i] == "--signature" and i + 1 < len(argv):
            args["signature"] = argv[i + 1]
            i += 2
        elif argv[i] == "--disasm_lines" and i + 1 < len(argv):
            args["disasm_lines"] = int(argv[i + 1])
            i += 2
        elif argv[i] == "--no_procedure":
            args["no_procedure"] = True
            i += 1
        elif argv[i] == "--no_qexit":
            args["no_qexit"] = True
            i += 1
        else:
            i += 1

    return args

# 全局变量：控制是否在任务完成/失败时退出 IDA
_no_qexit = False


def safe_qexit(exit_code):
    """
    安全退出函数，根据 --no_qexit 参数决定是否退出 IDA

    Args:
        exit_code: 退出码 (0 表示成功，非 0 表示失败)
    """
    global _no_qexit
    if _no_qexit:
        status = "SUCCESS" if exit_code == 0 else "FAILED"
        print(f"[*] Task {status} (exit code: {exit_code}), staying in IDA (--no_qexit)")
        return
    idc.qexit(exit_code)


def wait_auto():
    """等待 IDA 自动分析完成"""
    print("[*] Waiting for auto-analysis to complete...")
    ida_auto.auto_wait()
    print("[*] Auto-analysis completed.")

def load_symbol_mapping(mapping_path):
    """
    加载 SymbolMapping.yaml 文件

    Args:
        mapping_path: SymbolMapping.yaml 文件路径

    Returns:
        符号映射字典，格式为 {unmapped_name: mapped_name}
        例如: {"sub_140822108": "PspSetCreateProcessNotifyRoutine"}
    """
    if not os.path.exists(mapping_path):
        print(f"[!] Symbol mapping file not found: {mapping_path}")
        return {}

    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not data:
                return {}
            # 直接返回原始格式: {unmapped: mapped}
            # 例如: sub_140822108: PspSetCreateProcessNotifyRoutine
            return data
    except Exception as e:
        print(f"[!] Failed to load SymbolMapping.yaml: {e}")
        return {}


def get_function_address(func_name):
    """
    通过函数名获取函数起始地址

    Args:
        func_name: 函数名称

    Returns:
        函数起始地址，找不到返回 ida_idaapi.BADADDR
    """
    # 方法1: 使用 ida_name.get_name_ea
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
    if ea != ida_idaapi.BADADDR:
        return ea

    # 方法2: 遍历所有函数名查找
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        if name == func_name:
            return func_ea

    return ida_idaapi.BADADDR


def search_signature(signature_str):
    """
    使用特征码搜索内存地址

    Args:
        signature_str: 特征码字符串，如 "FB488D05????????4989" 或 "FB 48 8D 05 ?? ?? ?? ?? 49 89"
                      ?? 或 ? 表示通配符

    Returns:
        找到的第一个地址，未找到返回 ida_idaapi.BADADDR
    """
    # 规范化输入：移除空格
    sig = signature_str.replace(" ", "")

    # 将特征码转换为字节序列和掩码
    # 普通字节：值为实际值，掩码为 0xFF
    # 通配符 ??：值为 0x00，掩码为 0x00
    data_bytes = []
    mask_bytes = []
    i = 0
    while i < len(sig):
        if sig[i] == '?':
            # 通配符：可能是 ? 或 ??
            if i + 1 < len(sig) and sig[i + 1] == '?':
                data_bytes.append(0x00)
                mask_bytes.append(0x00)
                i += 2
            else:
                data_bytes.append(0x00)
                mask_bytes.append(0x00)
                i += 1
        else:
            # 普通字节：取两个字符
            if i + 1 < len(sig):
                byte_val = int(sig[i:i + 2], 16)
                data_bytes.append(byte_val)
                mask_bytes.append(0xFF)
                i += 2
            else:
                # 奇数长度，跳过最后一个字符
                i += 1

    data = bytes(data_bytes)
    mask = bytes(mask_bytes)

    # 打印搜索信息
    pattern_str = " ".join(f"{b:02X}" if m == 0xFF else "??" for b, m in zip(data_bytes, mask_bytes))
    print(f"[*] Searching for pattern: {pattern_str}")
    print(f"[*] Pattern length: {len(data)} bytes")

    # 获取搜索范围
    start_ea = ida_ida.inf_get_min_ea()
    end_ea = ida_ida.inf_get_max_ea()

    # 使用 find_bytes 搜索
    found_ea = ida_bytes.find_bytes(
        data,
        start_ea,
        range_end=end_ea,
        mask=mask,
        flags=ida_bytes.BIN_SEARCH_FORWARD
    )

    return found_ea


def rename_function(ea, new_name):
    """
    重命名函数

    Args:
        ea: 函数地址
        new_name: 新的函数名

    Returns:
        成功返回 True，失败返回 False
    """
    try:
        # 使用 ida_name.set_name 重命名
        # SN_CHECK: 检查名称是否有效
        # SN_NOWARN: 不显示警告
        result = ida_name.set_name(ea, new_name, ida_name.SN_CHECK | ida_name.SN_NOWARN)
        return result
    except Exception as e:
        print(f"[!] Failed to rename function at {hex(ea)} to {new_name}: {e}")
        return False


def get_image_base():
    """
    获取当前加载的 PE 文件的 ImageBase

    Returns:
        ImageBase 地址
    """
    # 使用 ida_nalt 获取 ImageBase
    import ida_nalt
    return ida_nalt.get_imagebase()


def apply_symbol_remap(mapping_path):
    """
    应用符号映射，将所有 unmapped 名称重命名为真实名称
    同时在 YAML 文件中添加 ImageBase 信息

    Args:
        mapping_path: SymbolMapping.yaml 文件路径

    Returns:
        (success_count, fail_count, skip_count) 元组
    """
    # 加载映射
    mappings = load_symbol_mapping(mapping_path)
    if not mappings:
        print("[!] No symbol mappings to apply")
        return 0, 0, 0

    print(f"[*] Loaded {len(mappings)} symbol mappings from: {mapping_path}")

    # 获取 ImageBase 并检查是否需要添加
    image_base = get_image_base()
    image_base_key = f"{image_base:X}"  # 转换为十六进制字符串，如 "140000000"

    # 检查是否已存在 ImageBase 条目
    if image_base_key not in mappings:
        # 添加 ImageBase 条目到映射中
        mappings[image_base_key] = "ImageBase"
        print(f"[*] Adding ImageBase entry: {image_base_key}: ImageBase")

        # 更新 YAML 文件
        try:
            with open(mapping_path, "w", encoding="utf-8") as f:
                yaml.dump(mappings, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"[+] Updated {mapping_path} with ImageBase")
        except Exception as e:
            print(f"[!] Failed to update YAML file with ImageBase: {e}")
    else:
        print(f"[*] ImageBase entry already exists: {image_base_key}")

    success_count = 0
    fail_count = 0
    skip_count = 0

    for unmapped_name, mapped_name in mappings.items():
        # 查找 unmapped 名称对应的地址
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, unmapped_name)
        if ea == ida_idaapi.BADADDR:
            print(f"  [-] Symbol not found: {unmapped_name}")
            skip_count += 1
            continue

        # 重命名
        if rename_function(ea, mapped_name):
            print(f"  [+] Renamed: {unmapped_name} -> {mapped_name} at {hex(ea)}")
            success_count += 1
        else:
            print(f"  [!] Failed to rename: {unmapped_name} -> {mapped_name}")
            fail_count += 1

    return success_count, fail_count, skip_count


def get_section_name(ea):
    """
    获取地址所在的段名称

    Args:
        ea: 地址

    Returns:
        段名称字符串，如 ".text"
    """
    seg = ida_segment.getseg(ea)
    if seg:
        return ida_segment.get_segm_name(seg)
    return ""


def format_address(ea):
    """
    格式化地址为 SECTION:OFFSET 格式

    Args:
        ea: 地址

    Returns:
        格式化的地址字符串，如 ".text:0000000140822108"
    """
    section = get_section_name(ea)
    if section:
        return f"{section}:{ea:016X}"
    return f"{ea:016X}"


def format_xref_address(ea):
    """
    格式化 xref 来源地址

    Args:
        ea: xref 来源地址

    Returns:
        格式化的地址字符串:
        - 如果在函数内: "函数名+0xXX"
        - 如果不在函数内: "段:偏移" 格式
    """
    func = ida_funcs.get_func(ea)
    if func:
        func_name = ida_funcs.get_func_name(func.start_ea)
        offset = ea - func.start_ea
        if offset == 0:
            return func_name
        return f"{func_name}+0x{offset:x}"
    else:
        # 不在函数内，使用 段:偏移 格式
        return format_address(ea)


def get_function_disassembly(func_ea, max_lines=None):
    """
    获取函数的反汇编代码

    Args:
        func_ea: 函数起始地址
        max_lines: 最大反汇编行数限制（None 表示不限制）

    Returns:
        反汇编代码字符串
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    lines = []
    instruction_count = 0

    # 获取函数名
    func_name = ida_funcs.get_func_name(func_ea)

    # 检查是否为导出函数并添加注释
    ordinal = get_export_ordinal(func_ea)
    if ordinal is not None:
        lines.append(f"; Exported entry {ordinal}. {func_name}")
        lines.append("")

    # 获取函数类型签名
    func_type = idc.get_type(func_ea)
    if func_type:
        lines.append("; " + func_type)

    # 添加 public 声明和函数头
    lines.append(f"{format_address(func_ea)}                 public {func_name}")
    lines.append(f"{format_address(func_ea)} {func_name}     proc near")

    # 遍历函数内的每条指令
    ea = func.start_ea
    truncated = False
    while ea < func.end_ea:
        # 检查是否达到行数限制
        if max_lines is not None and instruction_count >= max_lines:
            truncated = True
            break

        line_parts = []

        # 添加地址
        addr_str = format_address(ea)
        line_parts.append(addr_str)

        # 检查是否有标签（跳转目标等）
        name_at_ea = ida_name.get_name(ea)
        if name_at_ea and name_at_ea != func_name:
            # 这是一个标签行
            lines.append(f"{addr_str}")
            lines.append(f"{addr_str} {name_at_ea}:")

        # 生成反汇编行并移除颜色标签
        disasm_line = idc.generate_disasm_line(ea, 0)
        if disasm_line:
            clean_line = ida_lines.tag_remove(disasm_line)
            lines.append(f"{addr_str}                 {clean_line}")
            instruction_count += 1

        # 移动到下一条指令
        ea = idc.next_head(ea, func.end_ea)
        if ea == ida_idaapi.BADADDR:
            break

    # 添加截断提示或函数结束标记
    if truncated:
        lines.append(f"; ... (truncated, showing {max_lines} lines)")
    else:
        lines.append(f"{format_address(func.end_ea - 1)} {func_name}     endp")

    return "\n".join(lines)


def get_disassembly_from_address(start_ea, max_lines):
    """
    从指定地址开始获取反汇编代码（用于特征码搜索模式）

    Args:
        start_ea: 起始地址（特征码匹配的地址）
        max_lines: 最大反汇编行数限制

    Returns:
        反汇编代码字符串
    """
    lines = []
    instruction_count = 0

    # 获取包含该地址的函数（如果存在）
    func = ida_funcs.get_func(start_ea)
    end_ea = func.end_ea if func else ida_ida.inf_get_max_ea()

    # 获取该地址处的函数名（用于 public 声明）
    actual_func_name = ida_funcs.get_func_name(start_ea) if func else None

    # 添加 public 声明（显示特征码地址和函数名）
    if actual_func_name:
        lines.append(f"{format_address(start_ea)}                 public {actual_func_name}")
        lines.append(f"{format_address(start_ea)} {actual_func_name}     proc near")

    # 从特征码地址开始遍历
    ea = start_ea
    truncated = False
    while ea < end_ea:
        # 检查是否达到行数限制
        if max_lines is not None and instruction_count >= max_lines:
            truncated = True
            break

        # 添加地址
        addr_str = format_address(ea)

        # 检查是否有标签（跳转目标等）
        name_at_ea = ida_name.get_name(ea)
        if name_at_ea and name_at_ea != actual_func_name and instruction_count > 0:
            # 这是一个标签行
            lines.append(f"{addr_str}")
            lines.append(f"{addr_str} {name_at_ea}:")

        # 生成反汇编行并移除颜色标签
        disasm_line = idc.generate_disasm_line(ea, 0)
        if disasm_line:
            clean_line = ida_lines.tag_remove(disasm_line)
            lines.append(f"{addr_str}                 {clean_line}")
            instruction_count += 1

        # 移动到下一条指令
        ea = idc.next_head(ea, end_ea)
        if ea == ida_idaapi.BADADDR:
            break

    # 添加截断提示
    if truncated:
        lines.append(f"; ... (truncated, showing {max_lines} lines)")

    return "\n".join(lines)


def get_xrefs(ea):
    """
    获取函数或变量的所有交叉引用（被引用的位置）

    Args:
        ea: 函数起始地址或变量地址

    Returns:
        xref 信息列表，每项为 {"address": "...", "instruction": "..."}
    """
    xrefs = []

    for xref in idautils.XrefsTo(ea, 0):
        from_ea = xref.frm

        # 格式化来源地址
        addr_str = format_xref_address(from_ea)

        # 获取反汇编指令
        disasm_line = idc.generate_disasm_line(from_ea, 0)
        if disasm_line:
            instruction = ida_lines.tag_remove(disasm_line)
        else:
            instruction = ""

        xrefs.append({
            "address": addr_str,
            "instruction": instruction
        })

    return xrefs


def get_export_ordinal(ea):
    """
    获取函数的导出序号

    Args:
        ea: 函数地址

    Returns:
        导出序号，未导出返回 None
    """
    try:
        import ida_entry
        # 遍历所有导出项查找匹配地址
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            entry_ea = ida_entry.get_entry(ordinal)
            if entry_ea == ea:
                return ordinal
        return None
    except:
        return None

def get_function_pseudocode(func_ea):
    """
    获取函数的伪代码 (需要 Hex-Rays 反编译器)

    Args:
        func_ea: 函数起始地址

    Returns:
        伪代码字符串，失败返回 None
    """
    try:
        # 初始化 Hex-Rays 反编译器
        if not ida_hexrays.init_hexrays_plugin():
            print("[!] Hex-Rays decompiler is not available")
            return None

        # 反编译函数
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            print(f"[!] Failed to decompile function at {hex(func_ea)}")
            return None

        # 获取伪代码行
        pseudocode = cfunc.get_pseudocode()
        lines = []
        for line in pseudocode:
            # 移除颜色标签
            clean_line = ida_lines.tag_remove(line.line)
            lines.append(clean_line)

        return "\n".join(lines)

    except Exception as e:
        print(f"[!] Decompilation error: {e}")
        return None

def build_output_path(input_file, func_name):
    """
    根据输入文件路径和函数名生成输出文件路径

    Args:
        input_file: 输入的 PE 文件路径
        func_name: 函数名称

    Returns:
        输出 YAML 文件路径 (函数名.yaml)
    """
    # 优先使用 IDB 文件所在目录（更可靠）
    # 因为 idc.get_input_file_path() 返回的可能是 IDA 内部记录的路径，
    # 而 IDB 文件总是保存在用户指定的输入文件所在目录
    try:
        idb_path = idc.get_idb_path()
        if idb_path:
            input_dir = os.path.dirname(idb_path)
        else:
            input_dir = os.path.dirname(input_file)
    except:
        input_dir = os.path.dirname(input_file)

    # 使用函数名作为文件名
    return os.path.join(input_dir, f"{func_name}.yaml")

def export_function_info(func_name, func_ea, disasm_code, output_path, pseudocode=None):
    """
    导出函数信息到 YAML 文件

    Args:
        func_name: 函数名称
        func_ea: 函数地址
        disasm_code: 反汇编代码
        output_path: 输出文件路径
        pseudocode: F5 伪代码 (可选)
    """
    # 确保输出目录存在
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 构建数据结构
    data = {
        "virtualaddress": hex(func_ea),
        "disasm_code": disasm_code
    }

    # 如果有伪代码则添加 procedure 字段
    if pseudocode:
        data["procedure"] = pseudocode

    # 自定义 Dumper 使多行字符串使用 literal block 格式 (|)
    class LiteralDumper(yaml.SafeDumper):
        pass

    def literal_str_representer(dumper, data):
        if '\n' in data:
            # 多行字符串使用 literal block style
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    LiteralDumper.add_representer(str, literal_str_representer)

    with open(output_path, "w", encoding="utf-8") as fp:
        yaml.dump(data, fp, Dumper=LiteralDumper, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"[+] Exported to: {output_path}")


def export_xref_info(func_name, func_ea, xrefs, output_path):
    """
    导出 xref 信息到 YAML 文件

    Args:
        func_name: 函数名称
        func_ea: 函数地址
        xrefs: xref 列表
        output_path: 输出文件路径
    """
    # 确保输出目录存在
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    data = {
        "virtualaddress": hex(func_ea),
        "xrefs": xrefs
    }

    with open(output_path, "w", encoding="utf-8") as fp:
        yaml.dump(data, fp, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"[+] Exported {len(xrefs)} xrefs to: {output_path}")


def main():
    """主函数"""
    # 解析参数
    args = parse_script_args()
    mode = args["mode"]

    # 设置全局退出控制
    global _no_qexit
    _no_qexit = args["no_qexit"]

    print(f"[*] Mode: {mode}")

    # 等待自动分析完成
    wait_auto()

    # 获取当前数据库对应的输入文件路径
    input_file = idc.get_input_file_path()
    print(f"[*] Input file: {input_file}")

    # 根据模式执行不同的操作
    if mode == "symbol_remap":
        # 符号重映射模式
        if args["symbol_remap_file"]:
            mapping_path = args["symbol_remap_file"]
        else:
            # 默认使用 PE 同目录下的 SymbolMapping.yaml
            mapping_path = os.path.join(os.path.dirname(input_file), "SymbolMapping.yaml")

        print(f"[*] Symbol mapping file: {mapping_path}")

        # 应用符号映射
        success, fail, skip = apply_symbol_remap(mapping_path)
        print(f"\n[+] Symbol remap completed:")
        print(f"    Success: {success}")
        print(f"    Failed:  {fail}")
        print(f"    Skipped: {skip}")

        # headless 模式下退出
        safe_qexit(0 if fail == 0 else 1)
        return

    elif mode == "disasm":
        # 反汇编模式
        func_name = args["func"]
        signature = args["signature"]
        disasm_lines = args["disasm_lines"]
        no_procedure = args["no_procedure"]

        if not func_name:
            print("[!] Function name is required for disasm mode")
            print("    Usage: --mode disasm --func FuncName")
            print("           --mode disasm --signature HEXSTRING --func FuncName")
            safe_qexit(1)
            return

        print(f"[*] Target function: {func_name}")

        # 确定输出路径
        if args["output"]:
            output_path = args["output"]
        else:
            output_path = build_output_path(input_file, func_name)

        # 优先使用特征码搜索
        if signature:
            print(f"[*] Searching by signature: {signature}")
            func_ea = search_signature(signature)
            if func_ea == ida_idaapi.BADADDR:
                print(f"[!] Signature not found: {signature}")
                safe_qexit(1)
                return
            print(f"[+] Found signature at {hex(func_ea)}")
        else:
            # 回退到函数名查找
            func_ea = get_function_address(func_name)
            if func_ea == ida_idaapi.BADADDR:
                print(f"[!] Function '{func_name}' not found")
                safe_qexit(1)
                return
            print(f"[+] Found function '{func_name}' at {hex(func_ea)}")

        # 跳转到函数 (在 GUI 模式下有效)
        ida_kernwin.jumpto(func_ea)

        # 获取反汇编代码（带行数限制）
        disasm_code = get_function_disassembly(func_ea, max_lines=disasm_lines)
        if not disasm_code:
            print(f"[!] Failed to get disassembly for '{func_name}'")
            safe_qexit(1)
            return

        if disasm_lines:
            print(f"[+] Got disassembly for '{func_name}' (limited to {disasm_lines} lines)")
        else:
            print(f"[+] Got disassembly for '{func_name}'")

        # 根据 no_procedure 决定是否获取伪代码
        if no_procedure:
            pseudocode = None
            print(f"[*] Skipping pseudocode (--no_procedure)")
        else:
            # 获取 F5 伪代码
            pseudocode = get_function_pseudocode(func_ea)
            if pseudocode:
                print(f"[+] Got pseudocode for '{func_name}'")
            else:
                print(f"[*] No pseudocode available for '{func_name}' (Hex-Rays may not be available)")

        # 导出结果
        export_function_info(func_name, func_ea, disasm_code, output_path, pseudocode)

        # headless 模式下退出
        safe_qexit(0)

    elif mode == "xref":
        # xref 模式 - 支持 --func 或 --var
        func_name = args["func"]
        var_name = args["var"]

        if func_name:
            # 函数 xref 模式
            symbol_name = func_name
            symbol_type = "function"
            symbol_ea = get_function_address(func_name)
        elif var_name:
            # 变量 xref 模式
            symbol_name = var_name
            symbol_type = "variable"
            symbol_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, var_name)
        else:
            print("[!] Function or variable name is required for xref mode")
            print("    Usage: --mode xref --func FuncName")
            print("           --mode xref --var VarName")
            safe_qexit(1)
            return

        print(f"[*] Target {symbol_type}: {symbol_name}")

        # 确定输出路径
        if args["output"]:
            output_path = args["output"]
        else:
            output_path = build_output_path(input_file, symbol_name)

        # 检查符号是否找到
        if symbol_ea == ida_idaapi.BADADDR:
            print(f"[!] {symbol_type.capitalize()} '{symbol_name}' not found")
            safe_qexit(1)
            return

        print(f"[+] Found {symbol_type} '{symbol_name}' at {hex(symbol_ea)}")

        # 获取 xref 信息
        xrefs = get_xrefs(symbol_ea)
        print(f"[+] Found {len(xrefs)} xrefs to '{symbol_name}'")

        # 导出结果
        export_xref_info(symbol_name, symbol_ea, xrefs, output_path)

        # headless 模式下退出
        safe_qexit(0)

    else:
        print(f"[!] Unknown mode: {mode}")
        print("    Supported modes: disasm, xref, symbol_remap")
        safe_qexit(1)

if __name__ == "__main__":
    main()
