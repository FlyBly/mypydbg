# coding:utf-8
#反汇编引擎

from capstone import *
from ctypes import *

kernel32 = windll.kernel32


class MyAsm():
    def __init__(self, h_process):
        self.h_process = h_process
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

    #反汇编一条指令
    def AnitAsm(self,address):

        st_byte		= create_string_buffer(100)
        count		= c_ulong(0)

        kernel32.ReadProcessMemory(self.h_process, address, st_byte, 100, byref(count))

        for insn in self.md.disasm(st_byte,100):
            Asm =insn.mnemonic +" "+ insn.op_str


            Opcode=""
            for i in insn.bytes:
                Opcode += hex(i)+" "
            return Opcode,Asm,insn.size

    #返回下一条指令长度
    def AnitAsmALine(self,address):
        st_byte		= create_string_buffer(100)
        count		= c_ulong(0)

        kernel32.ReadProcessMemory(self.h_process, address, st_byte, 100, byref(count))

        for insn in self.md.disasm(st_byte,100):
            return insn.size
