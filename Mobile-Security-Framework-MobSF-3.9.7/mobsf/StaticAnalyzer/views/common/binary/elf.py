# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)


NA = 'Not Applicable'
NO_RELRO = 'No RELRO'
PARTIAL_RELRO = 'Partial RELRO'
FULL_RELRO = 'Full RELRO'
INFO = 'info'
WARNING = 'warning'
HIGH = 'high'

def nm_is_debug_symbol_stripped(elf_file):
    """使用操作系统实用程序检查是否剥离了调试符号。"""
    # https://linux.die.net/man/1/nm
    out = subprocess.check_output(
        [shutil.which('nm'), '--debug-syms', elf_file],
        stderr=subprocess.STDOUT)
    return b'no debug symbols' in out


class ELFChecksec:
    def __init__(self, elf_file, so_rel):
        self.elf_path = elf_file.as_posix()
        self.elf_rel = so_rel
        self.elf = lief.parse(self.elf_path)

    def checksec(self):
        elf_dict = {}
        elf_dict['name'] = self.elf_rel
        if not self.is_elf(self.elf_path):
            return
        is_nx = self.is_nx()
        if is_nx:
            severity = INFO
            desc = (
                '该二进制文件设置了NX位。 这将内存页标记为'
                '不可执行，从而使攻击者注入的shellcode不可执行。')
        else:
            severity = HIGH
            desc = (
                '该二进制文件没有设置NX位。 NX位'
                '通过将内存页标记为不可执行来提供对内存损坏利用的保护。'
                '使用选项 --noexecstack 或 -z noexecstack 将堆栈标记为'
                '不可执行。')
        elf_dict['nx'] = {
            'is_nx': is_nx,
            'severity': severity,
            'description': desc,
        }
        has_canary = self.has_canary()
        if has_canary:
            severity = INFO
            desc = (
                '此二进制文件在堆栈中添加了栈金丝雀值，'
                '以便它将被溢出返回地址的堆栈缓冲区覆盖。'
                '通过在函数返回之前验证金丝雀的完整性，可以检测到溢出。')
        else:
            severity = HIGH
            desc = (
                '此二进制文件没有在堆栈中添加栈金丝雀值。'
                '堆栈金丝雀用于检测和防止利用从'
                '覆盖返回地址。使用选项 '
                '-fstack-protector-all 启用堆栈金丝雀。'
                '除非使用Dart FFI，否则不适用于Dart/Flutter库。')
        elf_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        relro = self.relro()
        if relro == NA:
            severity = INFO
            desc = ('RELRO检查不适用于 '
                    'Flutter/Dart 二进制文件')
        elif relro == FULL_RELRO:
            severity = INFO
            desc = (
                '此共享对象已启用完整RELRO。'
                'RELRO确保GOT不能在易受攻击的ELF二进制文件中被'
                '覆盖。 在完整RELRO中，整个GOT（.got 和'
                '.got.plt）都标记为只读。')
        elif relro == PARTIAL_RELRO:
            severity = WARNING
            desc = (
                '此共享对象已启用部分RELRO。'
                'RELRO确保GOT不能在易受攻击的ELF二进制文件中被'
                '覆盖。 在部分RELRO中，GOT部分的非PLT部分'
                '是只读的，但.got.plt仍然是'
                '可写的。使用选项 -z,relro,-z,now 启用'
                '完整RELRO。')
        else:
            severity = HIGH
            desc = (
                '此共享对象未启用RELRO。'
                '整个GOT（.got 和'
                '.got.plt）都是可写的。没有这个编译器'
                '标志，全局变量上的缓冲区溢出可以'
                '覆盖GOT条目。使用选项'
                '-z,relro,-z,now 启用完整RELRO，仅'
                '-z,relro 启用部分RELRO。')
        elf_dict['relocation_readonly'] = {
            'relro': relro,
            'severity': severity,
            'description': desc,
        }
        rpath = self.rpath()
        if rpath:
            severity = HIGH
            desc = (
                '二进制文件设置了RPATH。 在某些情况下，'
                '攻击者可以滥用此功能来运行任意'
                '库以执行代码和特权'
                '升级。 只有在二进制文件链接到相同包中的私有'
                '库时，才应设置RPATH。删除编译器选项'
                '-rpath 以删除RPATH。')
            rpt = rpath.rpath
        else:
            severity = INFO
            desc = (
                '二进制文件没有设置运行时搜索路径'
                '或RPATH。')
            rpt = rpath
        elf_dict['rpath'] = {
            'rpath': rpt,
            'severity': severity,
            'description': desc,
        }
        runpath = self.runpath()
        if runpath:
            severity = HIGH
            desc = (
                '二进制文件设置了RUNPATH。 在某些情况下，'
                '攻击者可以滥用此功能或修改'
                '环境变量以运行任意'
                '库以执行代码和特权'
                '升级。 只有在二进制文件链接到相同包中的私有'
                '库时，才应设置RUNPATH。删除编译器选项'
                '--enable-new-dtags,-rpath 以删除RUNPATH。')
            rnp = runpath.runpath
        else:
            severity = INFO
            desc = (
                '二进制文件没有设置RUNPATH。')
            rnp = runpath
        elf_dict['runpath'] = {
            'runpath': rnp,
            'severity': severity,
            'description': desc,
        }
        fortified_functions = self.fortify()
        if fortified_functions:
            severity = INFO
            desc = ('二进制文件具有 '
                    f'以下强化函数：{fortified_functions}')
        else:
            if self.is_dart():
                severity = INFO
            else:
                severity = WARNING
            desc = ('二进制文件没有任何'
                    '强化函数。 强化函数'
                    '提供了缓冲区溢出检查，针对'
                    'glibc\'s 常见的不安全函数如'
                    'strcpy, gets 等。使用编译器选项'
                    '-D_FORTIFY_SOURCE=2 以强化函数。'
                    '此检查不适用于'
                    'Dart/Flutter 库。')
        elf_dict['fortify'] = {
            'is_fortified': bool(fortified_functions),
            'severity': severity,
            'description': desc,
        }
        is_stripped = self.is_symbols_stripped()
        if is_stripped:
            severity = INFO
            desc = '符号已剥离。'
        else:
            severity = WARNING
            desc = '符号可用。'
        elf_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return elf_dict

    def is_elf(self, elf_path):
        return lief.is_elf(elf_path)

    def is_nx(self):
        return self.elf.has_nx

    def is_dart(self):
        dart = ('_kDartVmSnapshotInstructions',
                'Dart_Cleanup')
        if any(i in self.strings() for i in dart):
            return True
        for symbol in dart:
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except lief.not_found:
                pass
        return False

    def has_canary(self):
        if self.is_dart():
            return True
        for symbol in ('__stack_chk_fail',
                       '__intel_security_cookie'):
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except lief.not_found:
                pass
        return False

    def relro(self):
        try:
            gnu_relro = lief.ELF.SEGMENT_TYPES.GNU_RELRO
            bind_now_flag = lief.ELF.DYNAMIC_FLAGS.BIND_NOW
            flags_tag = lief.ELF.DYNAMIC_TAGS.FLAGS
            flags1_tag = lief.ELF.DYNAMIC_TAGS.FLAGS_1
            now_flag = lief.ELF.DYNAMIC_FLAGS_1.NOW

            if self.is_dart():
                return NA

            if not self.elf.get(gnu_relro):
                return NO_RELRO

            flags = self.elf.get(flags_tag)
            bind_now = flags and bind_now_flag in flags

            flags1 = self.elf.get(flags1_tag)
            now = flags1 and now_flag in flags1

            if bind_now or now:
                return FULL_RELRO
            else:
                return PARTIAL_RELRO
        except lief.not_found:
            pass
        return NO_RELRO

    def rpath(self):
        try:
            rpath = lief.ELF.DYNAMIC_TAGS.RPATH
            return self.elf.get(rpath)
        except lief.not_found:
            return False

    def runpath(self):
        try:
            runpath = lief.ELF.DYNAMIC_TAGS.RUNPATH
            return self.elf.get(runpath)
        except lief.not_found:
            return False

    def is_symbols_stripped(self):
        try:
            return nm_is_debug_symbol_stripped(
                self.elf_path)
        except Exception:
            for i in self.elf.static_symbols:
                if i:
                    return False
            return True

    def fortify(self):
        fortified_funcs = []
        for function in self.elf.symbols:
            if isinstance(function.name, bytes):
                try:
                    function_name = function.name.decode('utf-8')
                except UnicodeDecodeError:
                    function_name = function.name.decode('utf-8', 'replace')
            else:
                function_name = function.name
            if function_name.endswith('_chk'):
                fortified_funcs.append(function.name)
        return fortified_funcs

    def strings(self):
        normalized = set()
        try:
            elf_strings = self.elf.strings
        except Exception:
            elf_strings = None
        if not elf_strings:
            elf_strings = strings_on_binary(self.elf_path)
        for i in elf_strings:
            if isinstance(i, bytes):
                continue
            normalized.add(i)
        return list(normalized)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.elf.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
