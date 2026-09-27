import re


def decode(s):
    out = []
    for ch in s:
        c = ord(ch) - 1
        if 0x62 <= c <= 0x79:
            c = 0xDB - c
        out.append(chr(c))
    return "".join(out)


_MEM = re.compile(r"^dword ptr \[0x([0-9a-f]+)\]$")
_STORE = re.compile(r"^dword ptr \[0x([0-9a-f]+)\], eax$")
_IMM = re.compile(r"^0x([0-9a-f]+)$")


def resolved_apis(rep, img, getproc_iat=0x416000):
    """Globals the loaders fill with GetProcAddress(decode(name)) -> API name.

    Two patterns: an inline decode followed by call [GetProcAddress], and a helper
    (handle, encoded name) that decodes and resolves. The result reaches its global
    with `mov [X], eax`, sometimes scheduled after the next argument push."""
    table = {getproc_iat: "GetProcAddress"}
    functions = sorted(rep.getFunctions(), key=lambda f: f.offset)
    for _ in range(3):
        getprocs = {a for a, n in table.items() if n == "GetProcAddress"}
        helpers = set()
        for f in functions:
            for ins in f.getInstructions():
                m = _MEM.match(ins.operands or "")
                if ins.mnemonic == "call" and m and int(m.group(1), 16) in getprocs and f.num_instructions < 60:
                    helpers.add(f.offset)
        for f in functions:
            last = None
            eax = None
            for ins in sorted(f.getInstructions(), key=lambda i: i.offset):
                ops = ins.operands or ""
                m = _IMM.match(ops)
                if ins.mnemonic == "push" and m:
                    s = img.string_at(int(m.group(1), 16), minlen=3)
                    if s:
                        last = s
                    continue
                if ins.mnemonic == "call":
                    m = _MEM.match(ops)
                    m2 = _IMM.match(ops)
                    target_is_getproc = m and int(m.group(1), 16) in getprocs
                    target_is_helper = m2 and int(m2.group(1), 16) in helpers
                    if (target_is_getproc or target_is_helper) and last and f.offset not in helpers:
                        eax = last if last == "GetProcAddress" else decode(last)
                    elif not (m2 and last):
                        eax = None
                    continue
                m = _STORE.match(ops)
                if ins.mnemonic == "mov" and m and eax:
                    table[int(m.group(1), 16)] = eax
                elif ins.mnemonic in ("mov", "xor", "pop", "lea") and ops.startswith("eax"):
                    eax = None
    return table
