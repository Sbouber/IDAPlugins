"""Altera Nios II processor module for IDA Pro.

References:

https://people.ece.cornell.edu/land/courses/ece5760/DE2/tut_nios2_introduction.pdf
http://www-ug.eecg.toronto.edu/desl/manuals/n2cpu_nii51017.pdf


The Nios II has 3 instruction formats:

I <RegA 5 bits><RegB 5 bits><Imm 16 bits><Opcode 6 bits>
J <Offset 26 bits><Opcode 6 bits>
R <RegA 5 bits><RegB 5 bits><RegC 5 bits><Opcode OPX 11 bits><0x3a 6 bits>


TODO:
 - trace SP
 - FIX: can't add comments
 - plt names in call

"""

import idaapi
from idaapi import *


NIOS2_REGISTERS = [
    "ZERO",
    "AT",
    "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18", "R19", "R20", "R21", "R22",
    "R23",
    "ET",
    "BT",
    "GP",
    "SP",
    "FP",
    "EA",
    "BA",
    "RA",
    # Fake segments
    "CS",
    "DS"
]


NIOS2_INSTR_OP = {
    0x00: {'name': 'call', 'feature': CF_USE1 | CF_CALL, 'format': 'J', 'type': 'call'},
    0x01: {'name': 'jmpi', 'feature': CF_USE1 | CF_JUMP | CF_STOP, 'format': 'J', 'type': 'jump'},
    0x03: {'name': 'ldbu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x04: {'name': 'addi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x05: {'name': 'stb', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'format': 'I', 'type': 'store'},
    0x06: {'name': 'br', 'feature': CF_USE1 | CF_JUMP | CF_STOP, 'format': 'J', 'type': 'jump'},
    0x07: {'name': 'ldb', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x08: {'name': 'cmpgei', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x10: {'name': 'cmplti', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x0b: {'name': 'ldhu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x0c: {'name': 'andi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x0d: {'name': 'sth', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'format': 'I', 'type': 'store'},
    0x0e: {'name': 'bge', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'format': 'I', 'type': 'cbranch'},
    0x0f: {'name': 'ldh', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x13: {'name': 'initda', 'feature': CF_USE1 | CF_USE2, 'format': 'I', 'type': 'skip'},
    0x14: {'name': 'ori', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x15: {'name': 'stw', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'format': 'I', 'type': 'store'},
    0x16: {'name': 'blt', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'format': 'I', 'type': 'cbranch'},
    0x17: {'name': 'ldw', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x18: {'name': 'cmpnei', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x1b: {'name': 'flushda', 'feature': CF_USE1 | CF_USE2, 'format': 'I', 'type': 'skip'},
    0x1c: {'name': 'xori', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x1e: {'name': 'bne', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'format': 'I', 'type': 'cbranch'},
    0x20: {'name': 'cmpeqi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x23: {'name': 'ldbuio', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x24: {'name': 'muli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x25: {'name': 'stbio', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'format': 'I', 'type': 'store'},
    0x26: {'name': 'beq', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'format': 'I', 'type': 'cbranch'},
    0x27: {'name': 'ldbio', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x28: {'name': 'cmpgeui', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x2b: {'name': 'ldhuio', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x2c: {'name': 'andhi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x2d: {'name': 'sthio', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'format': 'I', 'type': 'store'},
    0x2e: {'name': 'bgeu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'format': 'I', 'type': 'cbranch'},
    0x2f: {'name': 'ldhio', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x30: {'name': 'cmpltui', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x32: {'name': 'custom', 'feature': 0, 'format': 'I', 'type': 'skip'},
    0x33: {'name': 'initd', 'feature': CF_USE1 | CF_USE2, 'format': 'I', 'type': 'skip'},
    0x34: {'name': 'orhi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'},
    0x35: {'name': 'stwio', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'format': 'I', 'type': 'store'},
    0x36: {'name': "bltu", 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP, 'format': 'I', 'type': 'cbranch'},
    0x37: {'name': 'ldwio', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG2, 'format': 'I', 'type': 'load'},
    0x3a: {'name': 'R-type', 'feature': 0, 'format': 'R', 'type': 'skip'},
    0x3b: {'name': 'flushd', 'feature': CF_USE1 | CF_USE2, 'format': 'I', 'type': 'skip'},
    0x3c: {'name': 'xorhi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'format': 'I', 'type': 'binop'}

}

# OPX is used if OP=0x3a (R-type)
NIOS2_INSTR_OPX = {
    0x01: {'name': 'eret', 'feature': CF_STOP | CF_JUMP, 'type': 'skip'},
    0x02: {'name': 'roli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binopi'},
    0x03: {'name': 'rol', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x04: {'name': 'flushp', 'feature': 0, 'type': 'skip'},
    0x05: {'name': 'ret', 'feature': CF_STOP | CF_JUMP, 'type': 'skip'},
    0x06: {'name': 'nor', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x07: {'name': 'mulxuu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x08: {'name': 'cmpge', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x09: {'name': 'bret', 'feature': CF_STOP | CF_JUMP, 'type': 'skip'},
    0x0b: {'name': 'ror', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x0c: {'name': 'flushi', 'feature': CF_USE3, 'type': 'skip'},
    0x0d: {'name': 'jmp', 'feature': CF_USE3 | CF_STOP | CF_JUMP, 'type': 'uniopA'},
    0x0e: {'name': 'and', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x10: {'name': 'cmplt', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x12: {'name': 'slli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 | CF_SHFT, 'type': 'binopi'},
    0x13: {'name': 'sll', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 | CF_SHFT, 'type': 'binop'},
    0x16: {'name': 'or', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x17: {'name': 'mulxsu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x18: {'name': 'cmpne', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x1a: {'name': 'srli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 | CF_SHFT, 'type': 'binopi'},
    0x1b: {'name': 'srl', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 | CF_SHFT, 'type': 'binop'},
    0x1c: {'name': 'nextpc', 'feature': CF_USE1 | CF_CHG1, 'type': 'uniopC'},
    0x1d: {'name': 'callr', 'feature': CF_USE3 | CF_CHG3 | CF_CALL, 'type': 'uniopA'},
    0x1e: {'name': 'xor', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x1f: {'name': 'mulxss', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x20: {'name': 'cmpeq', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x24: {'name': 'divu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x25: {'name': 'div', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x26: {'name': 'rdctl', 'feature': CF_USE1 | CF_USE2 | CF_CHG2, 'type': 'uniopC'},
    0x27: {'name': 'mul', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x28: {'name': 'cmpgeu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x29: {'name': 'initi', 'feature': CF_USE1, 'type': 'skip'},
    0x2d: {'name': 'trap', 'feature': CF_USE1, 'type': 'skip'},
    0x2e: {'name': 'wrctl', 'feature': CF_USE1 | CF_USE2, 'type': 'uniopA'},
    0x30: {'name': 'cmpltu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x31: {'name': 'add', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x34: {'name': 'break', 'feature': CF_USE1, 'type': 'skip'},
    0x36: {'name': 'sync', 'feature': 0, 'type': 'skip'},
    0x39: {'name': 'sub', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
    0x3a: {'name': 'srai', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binopi'},
    0x3b: {'name': 'sra', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'type': 'binop'},
}

class nios2_processor_t(idaapi.processor_t):

    id = 0x8000 + 1
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    cnbits = 8
    dnbits = 8

    psnames = ['nios2']
    plnames = ['Altera Nios II']

    segreg_size = 0
    instruc_start = 0
    tbyte_size = 0

    assembler = {
    'flag' : ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
    'uflag' : 0,
    'name': "GNU assembler",
    'origin': ".org",
    'end': "end",
    'cmnt': ";",
    'ascsep': "\"",
    'accsep': "'",
    'esccodes': "\"'",
    'a_ascii': ".ascii",
    'a_byte': ".byte",
    'a_word': ".short",
    'a_dword': ".int",
    'a_qword': ".quad",
    'a_oword': ".int128",
    'a_float': ".float",
    'a_double': ".double",
    #'a_tbyte': "dt",
    #'a_dups': "#d dup(#v)",
    'a_bss': "dfs %s",
    'a_seg': "seg",
    'a_curip': ".",
    'a_public': "public",
    'a_weak': "weak",
    'a_extrn': ".extrn",
    'a_comdef': "",
    'a_align': ".align",
    'lbrace': "(",
    'rbrace': ")",
    'a_mod': "%",
    'a_band': "&",
    'a_bor': "|",
    'a_xor': "^",
    'a_bnot': "~",
    'a_shl': "<<",
    'a_shr': ">>",
    'a_sizeof_fmt': "size %s",
    }


    def get_frame_retsize(self, func_ea):
        return 0

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4 # Assume PTRSZ = 4 by default

        # Init registers
        self.regNames = NIOS2_REGISTERS

        for i in xrange(len(NIOS2_REGISTERS)):
            setattr(self, 'ireg_' + NIOS2_REGISTERS[i], i)

        self.regFirstSreg = self.ireg_CS
        self.regLastSreg  = self.ireg_DS
        self.regCodeSreg = self.ireg_CS
        self.regDataSreg = self.ireg_DS

        # Init instructions
        instructions = []
        i = 0
        for op in NIOS2_INSTR_OP.values():
            instructions.append({'name':op['name'], 'feature': op['feature']})
            setattr(self, 'itype_' + op['name'], i)
            i += 1

        for op in NIOS2_INSTR_OPX.values():
            instructions.append({'name':op['name'], 'feature': op['feature']})
            setattr(self, 'itype_' + op['name'], i)

            if op['name'] == 'ret':
                self.icode_return = i
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = i

        # Array of instructions
        self.instruc = instructions

        self.comments = {}


    def decode_J(self, op, opcode, flags, itype):
        self.cmd.Op1.type = o_near
        self.cmd.Op1.dtyp = dt_dword

        offset = op >> 6
        if opcode == 0x06:
            target = self.cmd.ea + 4 + offset
        else:
            target = (self.cmd.ea & 0xf0000000) + (offset * 4)

        self.cmd.Op1.addr = target

        print("Decoded jump, target = %x" % target)

    def decode_R(self, op, opcode, flags, itype):
        opx = (op >> 11) & 0x3f
        self.cmd.itype = len(NIOS2_INSTR_OP) + NIOS2_INSTR_OPX.keys().index(opx)
        print("OPX = %d" % opx)
        itype = NIOS2_INSTR_OPX[opx]['type']

        C = (op >> 17) & 0x1f
        B = (op >> 22) & 0x1f
        A = (op >> 27) & 0x1f
        imm5 = (op >> 6) & 0x1f

        # binop, binopi, skip, jump, uniopA, uniopC

        if itype == 'uniopA':
            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = A
        elif itype == 'uniopC':
            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = C
        elif itype == 'binop':
            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = C

            self.cmd.Op2.type = o_reg
            self.cmd.Op2.reg = A

            self.cmd.Op3.type = o_reg
            self.cmd.Op3.reg = B
        elif itype == 'binopi':
            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = C

            self.cmd.Op2.type = o_reg
            self.cmd.Op2.reg = A

            self.cmd.Op3.type = o_imm
            self.cmd.Op3.value = imm5
            self.cmd.Op3.dtyp = dt_word
        

    def decode_I(self, op, opcode, flags, itype):
        imm = (op & 0x3fffc0) >> 6
        A = (op & 0xf8000000) >> 27
        B = (op & 0x07c00000) >> 22

        print("decode_I: A=%d B=%d imm=%d" % (A, B, imm))

        if itype == 'binop':

            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = B

            self.cmd.Op2.type = o_reg
            self.cmd.Op2.reg = A

            self.cmd.Op3.type = o_imm
            self.cmd.Op3.value = imm
            self.cmd.Op3.dtyp = dt_word

            print("Decoded binop")

        elif itype == 'cbranch':
            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = A

            self.cmd.Op2.type = o_reg
            self.cmd.Op2.reg = B

            self.cmd.Op3.type = o_near
            self.cmd.Op3.dtyp = dt_word
            self.cmd.Op3.addr = self.cmd.ea + 4 + imm

        elif itype == 'load' or itype == 'store':
            
            self.cmd.Op1.type = o_reg
            self.cmd.Op1.reg = B

            self.cmd.Op2.type = o_displ
            self.cmd.Op2.reg = A
            self.cmd.Op2.dtyp = dt_word
            self.cmd.Op2.addr = imm


    def ana(self):
        print("ana called at %x" % cmd.ea)

        op = ua_next_long()
        opcode = op & 0x3f
        print("op = %x, opcode = %d" % (op, opcode))

        ins = NIOS2_INSTR_OP[opcode]
        flags = ins['feature']
        name = ins['name']
        iformat = ins['format']
        itype = ins['type']

        self.cmd.itype = NIOS2_INSTR_OP.keys().index(opcode)

        # Set to no operand
        for c in self.cmd:
            c.type = o_void

        if iformat == 'R':
            self.decode_R(op, opcode, flags, itype)
        elif iformat == 'J':
            self.decode_J(op, opcode, flags, itype)
        else:
            self.decode_I(op, opcode, flags, itype)

        return self.cmd.size

    def add_stkvar(self, v, n, flag):
        pfn = get_func(self.cmd.ea)
        if pfn and ua_stkvar2(self.cmd[n], fix_sign_32(v), flag):
            op_stkvar(self.cmd.ea, n)

    def handle_operand(self, op, isRead):
        uFlag     = self.get_uFlag()
        is_offs   = isOff(uFlag, op.n)
        dref_flag = dr_R if isRead else dr_W
        def_arg   = isDefArg(uFlag, op.n)
        optype    = op.type

        if optype == o_imm:
            # create xrefs to valid addresses
            """makeoff = False
            if self.cmd.itype == self.itype_ila and isLoaded(op.value):
                makeoff = True
            if makeoff and not def_arg:
                set_offset(self.cmd.ea, op.n, self.cmd.cs)
                is_offs = True
            if is_offs:
                ua_add_off_drefs(op, dr_O)
            """
            pass
        elif optype == o_displ:
            # create data xrefs and stack vars
            if is_offs:
                ua_add_off_drefs(op, dref_flag)
            elif may_create_stkvars() and not def_arg and op.reg == self.ireg_SP:
                # var_x(SP)
                self.add_stkvar(op.addr, op.n, STKVAR_VALID_SIZE)
        elif optype == o_mem:
            # create data xrefs
            ua_dodata2(op.offb, op.addr, op.dtyp)
            ua_add_dref(op.offb, op.addr, dref_flag)
        elif optype == o_near:
            # create code xrefs
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(op.offb, op.addr, fl)

    def emu(self):
        print("emu called at %x" % cmd.ea)
        Feature = self.cmd.get_canon_feature()

        flow = (Feature & CF_STOP == 0)
        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        return 1

    def outop(self, op):
        print("outop called at %x" % cmd.ea)

        if op.type == o_reg:
            print("Outputing register %s" % self.regNames[op.reg])
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            print("Outputing imm %x" % op.value)
            OutValue(op, OOFW_IMM | OOF_SIGNED)
        elif op.type in [o_near, o_mem]:
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
        elif op.type == o_displ:
            OutValue(op, OOF_ADDR | OOFW_16 | OOF_SIGNED)
            out_symbol('(')
            out_register(self.regNames[op.reg])
            out_symbol(')')

        return True

    def out(self):
        print("out called at %x" % cmd.ea)
        buf = idaapi.init_output_buffer(1024)
        OutMnem(15)

        if self.cmd[0].type != o_void:
            out_one_operand(0)

        for i in range(1, 4):
            op = self.cmd[i]

            if op.type == o_void:
                break

            out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        term_output_buffer()
        MakeLine(buf)





def PROCESSOR_ENTRY():
    return nios2_processor_t()