import collections
import string

import capstone as cs
import lief
from capstone import arm as csa
from capstone import x86 as csx
from smda.common.SmdaReport import SmdaReport

PRINTABLE = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")


class Image:
    def __init__(self, data):
        self.data = data
        self.bin = lief.parse(list(data))
        self.segs = []
        if isinstance(self.bin, lief.ELF.Binary):
            for s in self.bin.segments:
                if s.type == lief.ELF.Segment.TYPE.LOAD:
                    self.segs.append((s.virtual_address, s.virtual_address + s.physical_size, s.file_offset))
            self.base = min(a for a, _, _ in self.segs)
        else:
            ib = self.bin.optional_header.imagebase
            self.base = ib
            for s in self.bin.sections:
                self.segs.append((ib + s.virtual_address, ib + s.virtual_address + min(s.virtual_size or s.size, s.size), s.offset))
        self.lo = min(a for a, _, _ in self.segs)
        self.hi = max(b for _, b, _ in self.segs)

    def read(self, va, n):
        for a, b, off in self.segs:
            if a <= va < b:
                o = off + va - a
                return self.data[o : o + min(n, b - va)]
        return None

    def mapped(self, va):
        return self.lo <= va < self.hi

    def string_at(self, va, minlen=4):
        raw = self.read(va, 256)
        if not raw:
            return None
        out = bytearray()
        for c in raw:
            if c == 0:
                break
            if c not in PRINTABLE:
                return None
            out.append(c)
        if len(out) >= minlen:
            return out.decode()
        # utf-16le
        if len(raw) > 2 and raw[1] == 0:
            s = raw.decode("utf-16le", "ignore").split("\x00")[0]
            if len(s) >= minlen and all(ch in string.printable for ch in s):
                return s
        return None


STACK_X86 = {csx.X86_REG_ESP, csx.X86_REG_EBP, csx.X86_REG_RSP, csx.X86_REG_RBP}
STACK_ARM = {csa.ARM_REG_SP}


def features(report_path, data, imports=None, keep_small=False):
    """Architecture-neutral tokens per function: constants, strings, called imports."""
    rep = SmdaReport.fromFile(report_path) if isinstance(report_path, str) else report_path
    img = Image(data)
    if rep.architecture == "intel":
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32 if rep.bitness == 32 else cs.CS_MODE_64)
        mdt = None
    else:
        md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        mdt = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)
        mdt.detail = True
    md.detail = True
    imports = imports or {}
    out = {}
    for f in rep.getFunctions():
        toks = collections.Counter()
        thumb = bool((f.architecture_metadata or {}).get("thumb"))
        pending_lits = {}

        def emit(values, toks=toks):
            for kind, v, stackish in values:
                if img.mapped(v):
                    s = img.string_at(v)
                    if s:
                        toks["str:" + s] += 1
                    elif v in imports:
                        toks["api:" + imports[v]] += 1
                    continue
                if stackish:
                    continue
                sv = v - (1 << 32) if v & 0x80000000 else v
                if not keep_small and -0x10 <= sv <= 0x10:
                    continue
                toks["const:%#x" % v] += 1
            values.clear()

        for ins in sorted(f.getInstructions(), key=lambda i: i.offset):
            raw = bytes.fromhex(ins.bytes)
            dis = mdt if thumb else md
            try:
                d = next(dis.disasm(raw, ins.offset))
            except StopIteration:
                continue
            values = []
            if rep.architecture == "intel":
                regs = {op.reg for op in d.operands if op.type == csx.X86_OP_REG} | {op.mem.base for op in d.operands if op.type == csx.X86_OP_MEM}
                if d.group(cs.CS_GRP_CALL) or d.group(cs.CS_GRP_JUMP):
                    for op in d.operands:
                        if op.type == csx.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0 and op.mem.disp in imports:
                            toks["api:" + imports[op.mem.disp]] += 1
                        if op.type == csx.X86_OP_IMM and op.imm in imports:
                            toks["api:" + imports[op.imm]] += 1
                    continue
                for op in d.operands:
                    if op.type == csx.X86_OP_IMM:
                        values.append(("imm", op.imm & 0xFFFFFFFF, regs & STACK_X86))
                    elif op.type == csx.X86_OP_MEM:
                        if op.mem.base == 0 and op.mem.index == 0:
                            if op.mem.disp in imports:
                                toks["api:" + imports[op.mem.disp]] += 1
                            else:
                                values.append(("ptr", op.mem.disp & 0xFFFFFFFF, set()))
            else:
                if d.group(cs.CS_GRP_CALL) or d.group(cs.CS_GRP_JUMP):
                    for op in d.operands:
                        if op.type == csa.ARM_OP_IMM and op.imm in imports:
                            toks["api:" + imports[op.imm]] += 1
                    continue
                regs = {op.reg for op in d.operands if op.type == csa.ARM_OP_REG} | {op.mem.base for op in d.operands if op.type == csa.ARM_OP_MEM}
                ops = d.operands
                # position-independent address: rX = [literal]; add rX, pc
                if d.mnemonic.startswith("add") and len(ops) >= 2 and ops[0].type == csa.ARM_OP_REG and any(o.type == csa.ARM_OP_REG and o.reg == csa.ARM_REG_PC for o in ops[1:]):
                    src = [o.reg for o in ops[1:] if o.type == csa.ARM_OP_REG and o.reg != csa.ARM_REG_PC]
                    src = src[0] if src else ops[0].reg
                    if src in pending_lits:
                        lit = pending_lits.pop(src)
                        values.append(("lit", (lit + ins.offset + (4 if thumb else 8)) & 0xFFFFFFFF, set()))
                        emit(values)
                        continue
                for op in ops:
                    if op.type == csa.ARM_OP_IMM:
                        values.append(("imm", op.imm & 0xFFFFFFFF, regs & STACK_ARM))
                    elif op.type == csa.ARM_OP_MEM and op.mem.base == csa.ARM_REG_PC and d.mnemonic.startswith("ldr"):
                        pc = (ins.offset + (4 if thumb else 8)) & ~3
                        lit = img.read(pc + op.mem.disp, 4)
                        if lit and len(lit) == 4 and ops[0].type == csa.ARM_OP_REG:
                            reg = ops[0].reg
                            if reg in pending_lits:
                                values.append(("lit", pending_lits.pop(reg), set()))
                            pending_lits[reg] = int.from_bytes(lit, "little")
            emit(values)
        emit([("lit", v, set()) for v in pending_lits.values()])
        out[f.offset] = toks
    return rep, img, out
