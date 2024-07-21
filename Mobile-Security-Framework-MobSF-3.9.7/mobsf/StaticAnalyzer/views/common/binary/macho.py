# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess
from pathlib import Path

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)


def objdump_is_debug_symbol_stripped(macho_file):
    """使用操作系统实用程序检查是否剥离了调试符号。"""
    # https://www.unix.com/man-page/osx/1/objdump/
    # 仅适用于MacOS
    out = subprocess.check_output(
        [shutil.which('objdump'), '--syms', macho_file],
        stderr=subprocess.STDOUT)
    return b' d  ' not in out


class MachOChecksec:
    def __init__(self, macho, rel_path=None):
        self.macho_path = macho.as_posix()
        if rel_path:
            self.macho_name = rel_path
        else:
            self.macho_name = macho.name
        self.macho = lief.parse(self.macho_path)

    def checksec(self):
        macho_dict = {}
        macho_dict['name'] = self.macho_name

        if not self.is_macho(self.macho_path):
            return {}

        has_nx = self.has_nx()
        has_pie = self.has_pie()
        has_canary = self.has_canary()
        has_rpath = self.has_rpath()
        has_code_signature = self.has_code_signature()
        has_arc = self.has_arc()
        is_encrypted = self.is_encrypted()
        is_stripped = self.is_symbols_stripped()

        if has_nx:
            severity = 'info'
            desc = (
                '该二进制文件已设置NX位。 这将内存页标记为'
                '不可执行，使攻击者注入的shellcode不可执行。')
        else:
            severity = 'info'
            desc = (
                '该二进制文件没有设置NX位。 NX位'
                '通过将内存页标记为不可执行来提供保护，防止利用内存损坏'
                '漏洞。 但是，iOS从不允许应用程序从可写'
                '内存中执行代码。 您不需要专门启用'
                '‘NX位’，因为对于所有第三方代码，它始终是启用的。')
        macho_dict['nx'] = {
            'has_nx': has_nx,
            'severity': severity,
            'description': desc,
        }
        if has_pie:
            severity = 'info'
            desc = (
                '该二进制文件是使用 -fPIC 标志构建的，该标志'
                '启用了位置无关代码。 这使得返回'
                '面向编程（ROP）攻击更难以可靠地执行。')
        else:
            severity = 'high'
            ext = Path(self.macho_name).suffix
            # PIE 检查不适用于静态和动态库
            # https://github.com/MobSF/Mobile-Security-Framework-MobSF/
            # issues/2290#issuecomment-1837272113
            if (ext == '.dylib'
                    or (not ext and '.framework' in self.macho_name)):
                severity = 'info'
            desc = (
                '该二进制文件未使用位置无关代码标志构建。'
                '为了防止攻击者可靠地跳转到，例如，内存中的'
                '特定利用函数，地址空间布局随机化（ASLR）随机排列'
                '进程关键数据区域的地址空间位置，包括可执行文件的基址和'
                '堆栈、堆和库的位置。 使用编译器'
                '选项 -fPIC 启用位置无关代码。'
                '不适用于dylib和静态库。')
        macho_dict['pie'] = {
            'has_pie': has_pie,
            'severity': severity,
            'description': desc,
        }
        if has_canary:
            severity = 'info'
            desc = (
                '此二进制文件在堆栈中添加了栈金丝雀值，以便它将被'
                '溢出返回地址的堆栈缓冲区覆盖。'
                '通过在函数返回之前验证金丝雀的完整性，可以检测到溢出。')
        elif is_stripped:
            severity = 'warning'
            desc = (
                '此二进制文件已剥离调试符号。 我们无法确定'
                '是否启用了栈金丝雀。')
        else:
            severity = 'high'
            sw_msg = ''
            if 'libswift' in self.macho_name:
                severity = 'warning'
                sw_msg = ' 这可能适用于纯Swift dylib。'
            desc = (
                '此二进制文件没有在堆栈中添加栈'
                '金丝雀值。 堆栈金丝雀用于检测和防止利用从'
                '覆盖返回地址。 使用选项'
                f'-fstack-protector-all 启用堆栈金丝雀。{sw_msg}')
        macho_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        if has_arc:
            severity = 'info'
            desc = (
                '该二进制文件是使用自动引用计数'
                '（ARC）标志编译的。 ARC 是一种编译器'
                '功能，提供 Objective-C 对象的自动内存管理'
                '管理，并且是一种防止内存'
                '损坏漏洞的利用缓解机制。'
            )
        elif is_stripped:
            severity = 'warning'
            desc = (
                '此二进制文件已剥离调试符号。 我们无法确定'
                '是否启用了 ARC。')
        else:
            severity = 'high'
            desc = (
                '该二进制文件未使用自动引用计数'
                '（ARC）标志编译。 ARC 是一种编译器'
                '功能，提供 Objective-C 对象的自动内存'
                '管理，并保护内存不受损坏'
                '漏洞。 使用编译器选项'
                '-fobjc-arc 启用 ARC 或设置'
                '在项目配置中将 Objective-C 自动引用计数'
                '设置为 YES。')
        macho_dict['arc'] = {
            'has_arc': has_arc,
            'severity': severity,
            'description': desc,
        }
        if has_rpath:
            severity = 'warning'
            desc = (
                '该二进制文件已设置运行路径搜索路径 (@rpath)。'
                '在某些情况下，攻击者可以滥用此功能'
                '运行任意可执行文件以执行代码'
                '执行和特权提升。 删除编译器'
                '选项 -rpath 以删除 @rpath。')
        else:
            severity = 'info'
            desc = (
                '该二进制文件未设置运行路径搜索路径'
                '(@rpath)。')
        macho_dict['rpath'] = {
            'has_rpath': has_rpath,
            'severity': severity,
            'description': desc,
        }
        if has_code_signature:
            severity = 'info'
            desc = '此二进制文件具有代码签名。'
        else:
            severity = 'warning'
            desc = '此二进制文件没有代码签名。'
        macho_dict['code_signature'] = {
            'has_code_signature': has_code_signature,
            'severity': severity,
            'description': desc,
        }
        if is_encrypted:
            severity = 'info'
            desc = '此二进制文件已加密。'
        else:
            severity = 'warning'
            desc = '此二进制文件未加密。'
        macho_dict['encrypted'] = {
            'is_encrypted': is_encrypted,
            'severity': severity,
            'description': desc,
        }
        if is_stripped:
            severity = 'info'
            desc = '已剥离调试符号'
        else:
            severity = 'warning'
            desc = (
                '调试符号可用。要剥离'
                '调试符号，请设置“在复制期间剥离调试符号”为“是”，'
                '“部署后处理”为“是”，'
                '以及“剥离链接产品”为“是”'
                '项目的构建设置。')
        macho_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return macho_dict

    def is_macho(self, macho_path):
        return lief.is_macho(macho_path)

    def has_nx(self):
        return self.macho.has_nx

    def has_pie(self):
        return self.macho.is_pie

    def has_canary(self):
        stk_check = '___stack_chk_fail'
        stk_guard = '___stack_chk_guard'
        imp_func_gen = self.macho.imported_functions
        has_stk_check = any(
            str(func).strip() == stk_check for func in imp_func_gen)
        has_stk_guard = any(
            str(func).strip() == stk_guard for func in imp_func_gen)

        return has_stk_check and has_stk_guard

    def has_arc(self):
        for func in self.macho.imported_functions:
            if str(func).strip() in ('_objc_release', '_swift_release'):
                return True
        return False

    def has_rpath(self):
        return self.macho.has_rpath

    def has_code_signature(self):
        try:
            return self.macho.code_signature.data_size > 0
        except Exception:
            return False

    def is_encrypted(self):
        try:
            return bool(self.macho.encryption_info.crypt_id)
        except Exception:
            return False

    def is_symbols_stripped(self):
        try:
            return objdump_is_debug_symbol_stripped(self.macho_path)
        except Exception:
            # 根据 issues/1917#issuecomment-1238078359
            # 和 issues/2233#issue-1846914047
            # 调试符号剥离的二进制文件会添加 radr://5614542 符号
            # radr://5614542 符号添加回
            # 调试符号剥离的二进制文件
            for i in self.macho.symbols:
                if i.name.lower().strip() in (
                        '__mh_execute_header', 'radr://5614542'):
                    # __mh_execute_header 存在于
                    # 剥离和未剥离的二进制文件中
                    # 还要忽略 radr://5614542
                    continue
                if (i.type & 0xe0) > 0 or i.type in (0x0e, 0x1e):
                    # N_STAB 设置或 14，30

                    # N_STAB	0xe0  /* 如果设置了这些位中的任何一个，
                    # 则为符号调试条目 */ -> 224
                    # https://opensource.apple.com/source/xnu/xnu-201/
                    # EXTERNAL_HEADERS/mach-o/nlist.h
                    # 只有符号调试条目具有
                    # 设置了一些 N_STAB 位，并且如果
                    # 这些位中的任何一个被设置，则它是一个
                    # 符号调试条目（stab）。

                    # 确定调试符号
                    return False
            if 'radr://5614542' in self.get_symbols():
                return True
            return False

    def get_libraries(self):
        libs = []
        for i in self.macho.libraries:
            curr = '.'.join(str(x) for x in i.current_version)
            comp = '.'.join(str(x) for x in i.compatibility_version)
            lib = (f'{i.name} (兼容性版本: {comp}'
                   f', 当前版本: {curr})')
            libs.append(lib)
        return libs

    def strings(self):
        return strings_on_binary(self.macho_path)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.macho.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
