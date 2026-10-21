import time
import json
import re
import os
import capstone
from unicorn import *
from unicorn.arm64_const import *
import ida_segment
import idc
import ida_bytes
import idaapi
import ida_dbg

# ==============================
# 常量定义
# ==============================

DUMP_SINGLE_SEG_SIZE = 0x4000
ROUND_MAX = 50

# ==============================
# 全局变量
# ==============================

mu = None
md = None
last_registers = {}
dumped_range = []
trace_log = None
log_file = None
hooks = []
BASE = 0
tpidr_value = None
last_regs = None
run_range = (0, 0)

# ==============================
# 寄存器映射
# ==============================

REG_MAP = {
    # General purpose registers (64-bit)
    "x0": UC_ARM64_REG_X0,
    "x1": UC_ARM64_REG_X1,
    "x2": UC_ARM64_REG_X2,
    "x3": UC_ARM64_REG_X3,
    "x4": UC_ARM64_REG_X4,
    "x5": UC_ARM64_REG_X5,
    "x6": UC_ARM64_REG_X6,
    "x7": UC_ARM64_REG_X7,
    "x8": UC_ARM64_REG_X8,
    "x9": UC_ARM64_REG_X9,
    "x10": UC_ARM64_REG_X10,
    "x11": UC_ARM64_REG_X11,
    "x12": UC_ARM64_REG_X12,
    "x13": UC_ARM64_REG_X13,
    "x14": UC_ARM64_REG_X14,
    "x15": UC_ARM64_REG_X15,
    "x16": UC_ARM64_REG_X16,
    "x17": UC_ARM64_REG_X17,
    "x18": UC_ARM64_REG_X18,
    "x19": UC_ARM64_REG_X19,
    "x20": UC_ARM64_REG_X20,
    "x21": UC_ARM64_REG_X21,
    "x22": UC_ARM64_REG_X22,
    "x23": UC_ARM64_REG_X23,
    "x24": UC_ARM64_REG_X24,
    "x25": UC_ARM64_REG_X25,
    "x26": UC_ARM64_REG_X26,
    "x27": UC_ARM64_REG_X27,
    "x28": UC_ARM64_REG_X28,
    "x29": UC_ARM64_REG_X29,
    "x30": UC_ARM64_REG_X30,
    
    # General purpose registers (32-bit)
    "w0": UC_ARM64_REG_W0,
    "w1": UC_ARM64_REG_W1,
    "w2": UC_ARM64_REG_W2,
    "w3": UC_ARM64_REG_W3,
    "w4": UC_ARM64_REG_W4,
    "w5": UC_ARM64_REG_W5,
    "w6": UC_ARM64_REG_W6,
    "w7": UC_ARM64_REG_W7,
    "w8": UC_ARM64_REG_W8,
    "w9": UC_ARM64_REG_W9,
    "w10": UC_ARM64_REG_W10,
    "w11": UC_ARM64_REG_W11,
    "w12": UC_ARM64_REG_W12,
    "w13": UC_ARM64_REG_W13,
    "w14": UC_ARM64_REG_W14,
    "w15": UC_ARM64_REG_W15,
    "w16": UC_ARM64_REG_W16,
    "w17": UC_ARM64_REG_W17,
    "w18": UC_ARM64_REG_W18,
    "w19": UC_ARM64_REG_W19,
    "w20": UC_ARM64_REG_W20,
    "w21": UC_ARM64_REG_W21,
    "w22": UC_ARM64_REG_W22,
    "w23": UC_ARM64_REG_W23,
    "w24": UC_ARM64_REG_W24,
    "w25": UC_ARM64_REG_W25,
    "w26": UC_ARM64_REG_W26,
    "w27": UC_ARM64_REG_W27,
    "w28": UC_ARM64_REG_W28,
    "w29": UC_ARM64_REG_W29,
    "w30": UC_ARM64_REG_W30,
    
    # Special registers
    "pc": UC_ARM64_REG_PC,
    "sp": UC_ARM64_REG_SP,
    "fp": UC_ARM64_REG_X29,
    "lr": UC_ARM64_REG_X30
}

# ==============================
# 内存管理函数
# ==============================

def load_file(path, start, size):
    """从文件加载数据到模拟器内存"""
    with open(path, "rb") as fp:
        mu.mem_write(start, fp.read())

def load_registers(path):
    """从JSON文件加载寄存器状态"""
    with open(path) as f:
        registers = json.load(f)
        for reg_name, value in registers.items():
            if reg_name in REG_MAP:
                if isinstance(value, str):
                    value = int(value, 16)
                print(f"Setting {reg_name} to {hex(value)}")
                mu.reg_write(REG_MAP[reg_name], value)

def dump_registers():
    """保存或返回所有寄存器状态"""
    registers = {}
    for reg_name, reg_const in REG_MAP.items():
        try:
            value = mu.reg_read(reg_const)
            registers[reg_name] = value
        except Exception as e:
            registers[reg_name] = f"Error: {str(e)}"
    
    result = ["Register Dump:"]
    for reg_name in sorted(registers.keys()):
        value = registers[reg_name]
        if isinstance(value, int):
            result.append(f"  {reg_name:8} = {hex(value)}")
        else:
            result.append(f"  {reg_name:8} = {value}")
    return "\n".join(result)

# ==============================
# 工具函数
# ==============================

def bytearray_to_int(byte_array):
    """字节数组转整数（小端序）"""
    return int.from_bytes(byte_array, byteorder='little')

def read_pointer(address):
    """从指定地址读取指针"""
    return bytearray_to_int(mu.mem_read(address, 4))

def extract_bit_field(input_value, start_bit, end_bit):
    """提取位字段"""
    mask = (~(-1 << (end_bit - start_bit)) << start_bit)
    return (mask & input_value) >> start_bit

def read_reg_from_instruction(inst_input, index):
    """从指令中读取寄存器值"""
    return mu.reg_read(REG_MAP[inst_input.reg_name(inst_input.operands[index].value.reg)])

# ==============================
# Hook处理函数
# ==============================

def my_malloc_impl(size):
    """malloc实现"""
    print(f"[+] malloc size {hex(size)}")

def my_malloc_handler(uc, address, size, user_data):
    """malloc hook处理"""
    print(f"[+] INTO Malloc {mu.reg_read(UC_ARM64_REG_X0)} LR = {hex(mu.reg_read(UC_ARM64_REG_LR))}")
    uc.reg_write(UC_ARM64_REG_X0, my_malloc_impl(mu.reg_read(UC_ARM64_REG_X0)))
    uc.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))

def my_free_handler(uc, address, size, user_data):
    """free hook处理"""
    print(f"[+] free NOP")
    uc.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))

def my_memset_impl(ptr, value, num):
    """memset实现"""
    print(f"[+] memset ptr {hex(ptr)}, value {hex(value)}, size {hex(num)}")
    return ptr

def my_memset_handler(uc, address, size, user_data):
    """memset hook处理"""
    print(f"[+] INTO Memset")
    ptr = mu.reg_read(UC_ARM64_REG_X0)
    value = mu.reg_read(UC_ARM64_REG_X1)
    num = mu.reg_read(UC_ARM64_REG_X2)
    
    result = my_memset_impl(ptr, value, num)
    
    uc.reg_write(UC_ARM64_REG_X0, result)
    uc.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))

# ==============================
# 内存访问分析
# ==============================

def analyze_memory_access(insn, address):
    """分析指令的内存访问模式"""
    memory_accesses = []
    
    READ_INSTRUCTIONS = ['ldr', 'ldrb', 'ldrh', 'ldp', 'ldur', 'ldurb', 'ldurh', 'ldxr', 'ldar']
    WRITE_INSTRUCTIONS = ['str', 'strb', 'strh', 'stp', 'stur', 'sturb', 'sturh', 'stxr', 'star']
    READ_WRITE_INSTRUCTIONS = ['ldaxr', 'stlxr']
    
    for op in insn.operands:
        if op.type == capstone.CS_OP_MEM:
            mem = op.value.mem
            base_reg = insn.reg_name(mem.base) if mem.base != 0 else None
            index_reg = insn.reg_name(mem.index) if mem.index != 0 else None
            disp = mem.disp
            
            try:
                base_val = mu.reg_read(REG_MAP[base_reg]) if base_reg else 0
                index_val = mu.reg_read(REG_MAP[index_reg]) if index_reg else 0
                
                mem_addr = base_val
                if index_reg:
                    if hasattr(mem, 'scale') and mem.scale != 1:
                        mem_addr += index_val * mem.scale
                    else:
                        mem_addr += index_val
                mem_addr += disp
                mem_addr = mem_addr & 0xFFFFFFFFFFFFFFFF
                
                # 处理读取指令
                if any(insn.mnemonic.startswith(prefix) for prefix in READ_INSTRUCTIONS):
                    size = _get_memory_access_size(insn)
                    try:
                        data = mu.mem_read(mem_addr, size)
                        hex_bytes = data.hex()
                        if 'p' in insn.mnemonic and size == 16 and len(hex_bytes) != 32:
                            hex_bytes = hex_bytes.ljust(32, '0')[:32]
                        memory_accesses.append(f"mr=0x{mem_addr:x}:{hex_bytes}")
                    except Exception as e:
                        print(f"内存读取错误: {e} - 指令: {insn.mnemonic} {insn.op_str}")
                
                # 处理写入指令
                elif any(insn.mnemonic.startswith(prefix) for prefix in WRITE_INSTRUCTIONS):
                    if len(insn.operands) >= 2 and insn.operands[0].type == capstone.CS_OP_REG:
                        src_reg = insn.reg_name(insn.operands[0].value.reg)
                        try:
                            reg_val = 0 if src_reg in ['wzr', 'xzr'] else mu.reg_read(REG_MAP[src_reg])
                            size, data = _get_write_data(insn, src_reg, reg_val)
                            hex_bytes = data.hex()
                            if 'p' in insn.mnemonic and size == 16 and len(hex_bytes) != 32:
                                hex_bytes = hex_bytes.ljust(32, '0')[:32]
                            memory_accesses.append(f"mw=0x{mem_addr:x}:{hex_bytes}")
                        except Exception as e:
                            print(f"内存写入错误: {e} - 指令: {insn.mnemonic} {insn.op_str}")
                            
            except Exception as e:
                print(f"计算内存地址错误: {e} - 指令: {insn.mnemonic} {insn.op_str}")
                
    return memory_accesses

def _get_memory_access_size(insn):
    """获取内存访问大小"""
    if 'b' in insn.mnemonic:  # 字节
        return 1
    elif 'h' in insn.mnemonic:  # 半字
        return 2
    elif 'p' in insn.mnemonic:  # 对加载/存储
        return 16
    elif insn.operands[0].type == capstone.CS_OP_REG:
        reg_name = insn.reg_name(insn.operands[0].value.reg)
        return 4 if reg_name.startswith('w') else 8
    else:
        return 8

def _get_write_data(insn, src_reg, reg_val):
    """获取写入数据"""
    if 'b' in insn.mnemonic:  # 字节
        return 1, (reg_val & 0xFF).to_bytes(1, 'little')
    elif 'h' in insn.mnemonic:  # 半字
        return 2, (reg_val & 0xFFFF).to_bytes(2, 'little')
    elif 'p' in insn.mnemonic:  # 对存储
        if len(insn.operands) >= 3 and insn.operands[1].type == capstone.CS_OP_REG:
            src_reg2 = insn.reg_name(insn.operands[1].value.reg)
            reg_val2 = 0 if src_reg2 in ['wzr', 'xzr'] else mu.reg_read(REG_MAP[src_reg2])
            return 16, reg_val.to_bytes(8, 'little') + reg_val2.to_bytes(8, 'little')
        else:
            return 8, reg_val.to_bytes(8, 'little')
    elif src_reg.startswith('w') or src_reg == 'wzr':  # 32位寄存器
        return 4, (reg_val & 0xFFFFFFFF).to_bytes(4, 'little')
    else:  # 64位寄存器
        return 8, reg_val.to_bytes(8, 'little')

# ==============================
# 寄存器跟踪
# ==============================

def log_changed_registers():
    """只记录发生变化的寄存器"""
    global last_registers
    
    TRACKED_REGS = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
        "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
        "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
        "x30", "sp", "pc"
    ]
    
    current_registers = {}
    changed_regs = []
    
    for reg_name in TRACKED_REGS:
        if reg_name in REG_MAP:
            value = mu.reg_read(REG_MAP[reg_name])
            current_registers[reg_name] = value
            
            if reg_name not in last_registers or last_registers[reg_name] != value:
                changed_regs.append((reg_name, value))
    
    last_registers.update(current_registers)
    
    if changed_regs:
        reg_output = [f"{reg_name.upper()}={hex(value)}" for reg_name, value in changed_regs]
        return ",".join(reg_output)
    return None

# ==============================
# 日志记录
# ==============================

def tenet_trace_log(address):
    """Trace钩子 - 通过分析汇编指令记录内存访问"""
    global trace_log
    
    code = mu.mem_read(address, 4)
    insn = next(md.disasm(code, address), None)
    
    if not insn:
        return
    
    memory_accesses = analyze_memory_access(insn, address)
    changed_regs_line = log_changed_registers()
    
    tmp_buffer = ""
    if changed_regs_line and trace_log:
        tmp_buffer += changed_regs_line + ","
    
    output_line = ""
    if memory_accesses:
        output_line += "," + ",".join(memory_accesses)
    if trace_log:
        trace_log.write(tmp_buffer + output_line + "\n")

def print_user_log(address):
    """用户日志记录"""
    offset = address - BASE
    code = mu.mem_read(address, 4)
    
    md.detail = True
    insn = next(md.disasm(code, address), None)
    
    if not insn:
        print(f"{hex(address):<12}: <Unknown Coding>", file=log_file)
        return

    content = _format_instruction_operands(insn)
    print(f"{hex(address):<12}: {insn.mnemonic:<8} {insn.op_str:<24} {content:<50}", file=log_file)

def _format_instruction_operands(insn):
    """格式化指令操作数"""
    content_parts = []
    
    for i, op in enumerate(insn.operands):
        if i > 0:
            content_parts.append(" ")
            
        if op.type == capstone.CS_OP_REG:
            reg_name = insn.reg_name(op.value.reg)
            try:
                reg_val = mu.reg_read(REG_MAP[reg_name])
                content_parts.append(f"{hex(reg_val)}")
            except KeyError:
                content_parts.append(f"<Unknown REG:{reg_name}>")
                
        elif op.type == capstone.CS_OP_IMM:
            content_parts.append(f"{hex(op.value.imm)}")
            
        elif op.type == capstone.CS_OP_MEM:
            mem = op.value.mem
            if mem.base != 0:
                base_reg = insn.reg_name(mem.base)
                try:
                    base_val = mu.reg_read(REG_MAP[base_reg])
                    content_parts.append(f"{hex(base_val)}")
                except KeyError:
                    content_parts.append(f"<Unknown REG:{base_reg}>")
                    
            if mem.index != 0:
                index_reg = insn.reg_name(mem.index)
                try:
                    index_val = mu.reg_read(REG_MAP[index_reg])
                    content_parts.append(f" {hex(index_val)}")
                except KeyError:
                    content_parts.append(f" <Unknown REG:{index_reg}>")
                    
            if mem.disp != 0:
                content_parts.append(f" {hex(mem.disp)}")
                
        elif op.type == capstone.CS_OP_FP:
            content_parts.append(f"{op.value.fp}")
            
        else:
            content_parts.append(f"<OPCODE TYPE:{op.type}>")
    
    return "".join(content_parts)

# ==============================
# 调试钩子
# ==============================

def debug_hook_code(uc, address, size, user_data):
    """调试钩子，用于其他调试目的"""
    global log_file, trace_log, run_range

    # 检查执行范围
    if address <= run_range[0] or address >= run_range[1]:
        print("OUT OF RANGE")
        raise UcError(0, f"Code Run out of range (0x{run_range[0]:x}, 0x{run_range[1]:x})")
    
    # 处理特殊指令
    code = mu.mem_read(address, 4)
    if code == b"\xBF\x23\x03\xD5":  # handle autiasp
        raise UcError(0, "Except AUTIASP")

    # 处理寄存器值修正
    _fix_register_values()
    
    # 调用 trace 日志记录函数
    if trace_log:
        tenet_trace_log(address)
    if log_file:
        print_user_log(address)

def _fix_register_values():
    """修正寄存器值"""
    for i in range(31):
        reg_tmp_num = mu.reg_read(REG_MAP[f"x{i}"])
        if reg_tmp_num & 0xb4ff000000000000 == 0xb400000000000000:
            reg_tmp_num = reg_tmp_num & 0xffffffffffffff
            mu.reg_write(REG_MAP[f"x{i}"], reg_tmp_num)

# ==============================
# 寄存器日志
# ==============================

def my_reg_logger():
    """打印寄存器状态"""
    print("PC :", hex(mu.reg_read(UC_ARM64_REG_PC)))
    print("SP :", hex(mu.reg_read(UC_ARM64_REG_SP)))
    print("NZCV:", hex(mu.reg_read(UC_ARM64_REG_NZCV)))
    
    reg_names = [
        ("x0", UC_ARM64_REG_X0), ("x1", UC_ARM64_REG_X1),
        ("x2", UC_ARM64_REG_X2), ("x3", UC_ARM64_REG_X3),
        ("x4", UC_ARM64_REG_X4), ("x5", UC_ARM64_REG_X5),
        ("x6", UC_ARM64_REG_X6), ("x7", UC_ARM64_REG_X7),
        ("x8", UC_ARM64_REG_X8), ("x9", UC_ARM64_REG_X9),
        ("x10", UC_ARM64_REG_X10), ("x11", UC_ARM64_REG_X11),
        ("x12", UC_ARM64_REG_X12), ("x13", UC_ARM64_REG_X13),
        ("x14", UC_ARM64_REG_X14), ("x15", UC_ARM64_REG_X15),
        ("x16", UC_ARM64_REG_X16), ("x17", UC_ARM64_REG_X17),
        ("x18", UC_ARM64_REG_X18), ("x19", UC_ARM64_REG_X19),
        ("x20", UC_ARM64_REG_X20), ("x21", UC_ARM64_REG_X21),
        ("x22", UC_ARM64_REG_X22), ("x23", UC_ARM64_REG_X23),
        ("x24", UC_ARM64_REG_X24), ("x25", UC_ARM64_REG_X25),
        ("x26", UC_ARM64_REG_X26), ("x27", UC_ARM64_REG_X27),
        ("x28", UC_ARM64_REG_X28), ("x29", UC_ARM64_REG_X29),
        ("x30", UC_ARM64_REG_X30)
    ]
    
    for i in range(0, len(reg_names), 4):
        for name, reg in reg_names[i:i+4]:
            value = mu.reg_read(reg)
            print(f"{name:<3}: {hex(value):<18}", end=" ")
        print()

def dump_memory(filename, address, size):
    """转储内存到文件"""
    with open(filename, "wb") as f:
        f.write(mu.mem_read(address, size))
    print(f"Memory dumped to {filename}")

# ==============================
# 主要模拟函数
# ==============================

def main_trace(so_name, end_addr, tenet_log_path=None, user_log_path="./uc.log", load_dumps_path="./dumps"):
    """主要模拟函数"""
    global trace_log, log_file, mu, last_registers, tpidr_value, last_regs, hooks
    
    try:        
        # 初始化模拟器
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        # 初始化日志文件
        trace_log, log_file = _init_log_files(tenet_log_path, user_log_path)
        
        # 加载内存映射
        _load_memory_mappings(load_dumps_path)
        
        # 设置线程指针
        if tpidr_value is not None:
            mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tpidr_value)

        # 加载寄存器状态
        load_registers(os.path.join(load_dumps_path, "regs.json"))
        print("Registers loaded.")  

        # 重置寄存器跟踪
        last_registers.clear()

        # 初始化trace日志
        if trace_log:
            _init_trace_log(so_name)

        # 设置调试钩子
        start_addr = mu.reg_read(REG_MAP["pc"])
        hooks.append(mu.hook_add(UC_HOOK_CODE, debug_hook_code, begin=start_addr))

        # 开始模拟
        mu.emu_start(start_addr, end_addr)

    except UcError as e:
        return _handle_uc_error(e)
    except Exception as e:
        print(f"发生未知错误: {e}")    
        my_reg_logger()
        return 0
    finally:
        print(f"Trace END!")
        # 清理资源
        if log_file:
            log_file.close()
        if trace_log:
            trace_log.close()
    
    return 114514

def _init_log_files(tenet_log_path, user_log_path):
    """初始化日志文件"""
    trace_log = None
    log_file = None
    
    if tenet_log_path:
        trace_log = open(tenet_log_path, "w")
    
    if user_log_path:
        log_file = open(user_log_path, "w")
    
    return trace_log, log_file

def _load_memory_mappings(load_dumps_path):
    """加载内存映射"""
    mem_list = os.listdir(load_dumps_path)
    map_list = []
    
    # 解析内存映射文件
    for filename in mem_list:
        pattern = r'0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)\.bin$'
        match = re.search(pattern, filename)
        if match:
            mem_base = int(match.group(1), 16)
            mem_end = int(match.group(2), 16)
            mem_size = int(match.group(3), 16)
            map_list.append((mem_base, mem_end, mem_size, filename))

    # 按照内存基址排序后加载
    map_list.sort(key=lambda x: x[0])
    tmp = (0, 0, 0, "")
    
    for mem_base, mem_end, mem_size, filename in map_list:
        # 内存对齐处理
        if mem_base < tmp[1]:
            mem_base = tmp[1]
        elif mem_base & 0xfff != 0:
            mem_base = mem_base & 0xfffffffffffff000

        mem_size = mem_end - mem_base
        if mem_size <= 0:
            mem_size = 0x1000
        elif mem_size & 0xfff != 0:
            mem_size = (mem_size & 0xfffffffffffff000) + 0x1000

        mem_end = mem_base + mem_size
        tmp = (mem_base, mem_end, mem_size, filename)
        
        print(f"map file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}")
        mu.mem_map(mem_base, mem_size)

    # 加载内存数据
    for mem_base, mem_end, mem_size, filename in map_list:
        print(f"write file {filename} {hex(mem_base)} {hex(mem_end)} {hex(mem_size)}")
        load_file(os.path.join(load_dumps_path, filename), mem_base, mem_size)

def _init_trace_log(so_name):
    """初始化trace日志"""
    trace_log.write(f"# SO: {so_name} @ {hex(BASE)}\n")
    
    # 记录初始寄存器状态
    tracked_regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
                   "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
                   "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
                   "x30", "sp", "pc"]
    
    initial_regs = []
    for reg_name in tracked_regs:
        if reg_name in REG_MAP:
            value = mu.reg_read(REG_MAP[reg_name])
            initial_regs.append(f"{reg_name.upper()}={hex(value)}")
            last_registers[reg_name] = value
    
    trace_log.write(",".join(initial_regs) + "\n")

def _handle_uc_error(e):
    """处理Unicorn错误"""
    global last_regs
    
    print("ERROR: %s" % e)
    err_str = "%s" % e
    my_reg_logger()

    if e.errno == 0:
        if "Code Run out of range" in e.args[0]:
            return _handle_out_of_range_error()
        if "Except AUTIASP" in e.args[0]:
            return _handle_autiasp_error()

    if "UC_ERR_EXCEPTION" in err_str:
        return _handle_exception_error()
        
    if last_regs == dump_registers():
        print(f"[!] Stop at the same location. Jump out. Maybe Check TPIDR regs")
        return 0
    
    if any(err in err_str for err in ["UC_ERR_READ_UNMAPPED", "UC_ERR_FETCH_UNMAPPED", "UC_ERR_WRITE_UNMAPPED"]):
        last_regs = dump_registers()
        return 2
    
    return 0

def _handle_out_of_range_error():
    """处理超出范围错误"""
    if check_registers():
        print('[!] Check REGs Wrong')
        exit(0)

    print(f"[+] Run to 0x{mu.reg_read(REG_MAP['lr']):x} for further run, PC: 0x{mu.reg_read(REG_MAP['pc']):x} ")
    ida_dbg.run_to(mu.reg_read(REG_MAP['lr']))
    print("[+] Waiting Ida...")
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    print(f"[+] Restart this Script until finish")
    return 1

def _handle_autiasp_error():
    """处理AUTIASP错误"""
    if check_registers():
        print('[!] Check REGs Wrong')
        exit(0)

    print(f"[+] Run to 0x{mu.reg_read(REG_MAP['pc']) + 4:x} for further run, PC: 0x{mu.reg_read(REG_MAP['pc']):x} ")
    ida_dbg.run_to(mu.reg_read(REG_MAP['pc']) + 4)
    print("[+] Waiting Ida...")
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    print(f"[+] Restart this Script until finish")
    return 1

def _handle_exception_error():
    """处理异常错误"""
    if check_registers():
        print('[!] Check REGs Wrong')
        exit(0)
    
    ida_dbg.run_to(mu.reg_read(REG_MAP['lr']))
    print("[+] Waiting Ida...")
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    print(f"[+] Restart this Script until finish")
    return 1

# ==============================
# 内存转储函数
# ==============================

def dump_segment_to_file(seg_start, seg_end, filename):
    """转储段数据到文件"""
    try:
        seg_size = seg_end - seg_start
        if seg_size <= 0:
            print(f"[-] Invalid segment size: {seg_size}")
            return False
        
        if seg_size > 0x4000000:
            print(f"[!] Too big segment size: {seg_size}")
            seg_size = 0x4000000
        
        segment_data = ida_bytes.get_bytes(seg_start, seg_size)
        if not segment_data:
            print(f"[-] Failed to read segment data from {hex(seg_start)} to {hex(seg_end)}")
            return False
        
        with open(filename, 'wb') as f:
            f.write(segment_data)
        
        print(f"[+] Successfully dumped segment to: {filename}")
        print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
        print(f"[+] Dumped size: {len(segment_data)} bytes ({hex(len(segment_data))})")
        return True
        
    except Exception as e:
        print(f"[-] Error during dump: {str(e)}")
        return False

def find_segment_by_address(target_addr):
    """通过地址查找段"""
    try:
        if isinstance(target_addr, str):
            addr_val = int(target_addr, 16) if target_addr.startswith('0x') else int(target_addr)
        else:
            addr_val = target_addr
    except ValueError:
        print(f"[-] Invalid address format: {target_addr}")
        return None
    
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg and seg.start_ea <= addr_val < seg.end_ea:
            return seg
    
    print(f"[-] No segment found containing address: {hex(addr_val)}")
    return None

def dump_single_segment_address(input_addr, range_size=0x10000, file_dump_path="./dumps", next_dump_flag=False):
    """转储单个段地址"""
    global dumped_range
    
    if not input_addr:
        print("[-] No address provided")
        return
    
    if isinstance(input_addr, str):
        target_addr = int(input_addr[2:], 16) if input_addr.startswith('0x') else int(input_addr)
    else:
        target_addr = input_addr

    # 处理特殊地址格式
    if target_addr & 0xb4ff000000000000 == 0xb400000000000000:
        target_addr = target_addr & 0xffffffffffffff
    
    seg = find_segment_by_address(target_addr)
    if not seg:
        print(f"[+] {target_addr} do not contain the addr")
        return
    
    # 计算转储范围
    if range_size < 0x10000:
        dump_base = target_addr & (~(0x1000 - 1))
    else:
        dump_base = target_addr & (~(range_size - 1))

    seg_start = seg.start_ea
    seg_end = seg.end_ea
    seg_name = ida_segment.get_segm_name(seg)
    
    print(f"[+] Found segment: {seg_name}")
    print(f"[+] Segment range: {hex(seg_start)} - {hex(seg_end)}")
    print(f"[+] Segment size: {hex(seg_end - seg_start)} bytes")
    
    dump_end = dump_base + range_size
    if dump_end > seg_end:
        dump_end = seg_end
    if dump_base < seg_start:
        dump_base = seg_start
    
    # 检查是否已转储
    for exist_start, exist_end in dumped_range:
        if dump_base > exist_start and dump_base < exist_end:
            dump_base = exist_end
        if dump_end > exist_start and dump_end < exist_end:
            dump_end = exist_start
    
    if dump_base >= dump_end:
        print(f"[+] Range {hex(dump_base)} - {hex(dump_end)} already dumped")
        return
    
    dumped_range.append((dump_base, dump_end))
    
    # 生成输出文件名
    filename = f"{file_dump_path}/segment_{seg_name}_{hex(dump_base)}_{hex(dump_end)}_{hex(dump_end - dump_base)}.bin"
    
    # 转储段到文件
    dump_segment_to_file(dump_base, dump_end, filename)

    # 处理跨段读写
    if next_dump_flag and seg_end - seg_start < 0x1000:
        dump_single_segment_address(seg_end + 100, 0x1000, file_dump_path, False)

def dump_registers_memory():    
    """转储寄存器指向的内存"""
    global dump_path
    for reg_name in REG_MAP.keys():
        if "w" in reg_name:
            continue
        dump_single_segment_address(mu.reg_read(REG_MAP[reg_name]), DUMP_SINGLE_SEG_SIZE, dump_path, True)

def check_registers():
    """检查寄存器一致性"""
    global mu
    ida_dbg.run_to(mu.reg_read(REG_MAP["pc"]))
    print("[+] Waiting Ida...")
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

    for reg_name in REG_MAP.keys():
        if "w" in reg_name:
            continue
        uc_value = mu.reg_read(REG_MAP[reg_name])
        ida_value = idc.get_reg_value(reg_name)
        if ida_value & 0xb4ff000000000000 == 0xb400000000000000:
            ida_value = ida_value & 0xffffffffffffff
        print(f"{reg_name} uc: 0x{uc_value:x} ida: 0x{ida_value:x}")
        if uc_value != ida_value:
            return True 
    return False

# ==============================
# 主函数
# ==============================

def main(endaddr_relative:int, so_name: str = "",tpidr_value_input: int = None, enable_tenet=False, user_path:str = "."):
    """主函数"""
    global md, mu, BASE, tpidr_value, run_range, dump_path, dumped_range
    
    dump_round = 0
    while dump_round < ROUND_MAX:
        print("Emulate ARM64 code")
        
        # 初始化
        dumped_range = []
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True
        
        mu = None
        last_registers.clear()
        
        BASE = 0
        tpidr_value = None
        last_regs = None
        run_range = (0, 0)
        
        trace_log = None
        log_file = None
        
        # 创建转储目录
        now_time_stamp = str(int(time.time()))
        dump_path = f"{user_path}/dump_{now_time_stamp}"
        os.mkdir(dump_path)

        # 收集寄存器状态
        registers = _collect_register_state()
        
        BASE = idaapi.get_imagebase()
        file_size = os.path.getsize(idc.get_input_file_path())
        run_range = (BASE, BASE + file_size)

        print(f"[+] BASE = {hex(BASE)}")
        print("[+] DUMPING memory")
        
        # 转储寄存器指向的内存
        for reg_value in registers.values():
            dump_single_segment_address(reg_value, DUMP_SINGLE_SEG_SIZE, dump_path, True)
        
        # 保存寄存器状态
        print("[+] DUMPING registers")
        with open(f"{dump_path}/regs.json", "w+") as f:
            json.dump(registers, f)

        BASE = idaapi.get_imagebase()
        tpidr_value = tpidr_value_input
        end_addr = BASE + endaddr_relative
        result_code = 11400
        if enable_tenet:
            _tenet_log_path = f"{dump_path}/tenet.log"
        else:
            _tenet_log_path = None

        # 执行模拟
        while result_code != 114514:
            result_code = main_trace(so_name, end_addr, 
                                   user_log_path=f"{dump_path}/uc.log", 
                                   tenet_log_path=_tenet_log_path,
                                   load_dumps_path=dump_path)
            if result_code == 1:
                break
            if result_code == 2:
                print("Update Memory")
                dump_registers_memory()
            if result_code == 0:
                break

        dump_round += 1
        
        # 检查退出条件
        if result_code == 1:
            print("[+] restart ")
            continue
        
        if result_code == 0:
            print("[!] Something Wrong")
            break

        # 检查最终状态
        if mu.reg_read(REG_MAP["pc"]) == end_addr:
            if check_registers():
                print("[!] REGs check Wrong, Breakpoint could lead to this error")
            else:
                print("[+] Finish!")
        else:
            print("[!] Something Wrong")
        break

def _collect_register_state():
    """收集寄存器状态"""
    registers = {}
    registers["sp"] = hex(idc.get_reg_value("sp"))
    registers["pc"] = hex(idc.get_reg_value("pc"))
    
    for i in range(31):
        reg_value = idc.get_reg_value(f"x{i}")
        # 处理特殊地址格式
        if reg_value & 0xb4ff000000000000 == 0xb400000000000000:
            reg_value = reg_value & 0xffffffffffffff
        print(f"x{i} = " + hex(reg_value))
        registers[f"x{i}"] = hex(reg_value)
    
    base = idaapi.get_imagebase()
    registers["base"] = hex(base)
    
    return registers

if __name__ == "__main__":
    main(0x0000, so_name="Target.so")