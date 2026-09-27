import lief

# OS-level APIs by what they do, so that a Win32 import and its POSIX counterpart share a token.
# POSIX code writes a socket with write() where Win32 calls send(), and closes a file and a socket
# with the same close() where Win32 splits CloseHandle from closesocket. A port preserves the
# operation, not the name, so those share one token.
CONCEPTS = {
    "socket": ["socket"],
    "connect": ["connect"],
    "select": ["select", "__WSAFDIsSet"],
    "io_write": ["send", "WriteFile", "fwrite", "write"],
    "io_read": ["recv", "ReadFile", "fread", "read"],
    "setsockopt": ["setsockopt"],
    "shutdown": ["shutdown"],
    "inet_addr": ["inet_addr"],
    "htons": ["htons", "ntohs"],
    "htonl": ["htonl", "ntohl"],
    "gethostbyname": ["gethostbyname"],
    "bind": ["bind"],
    "listen": ["listen"],
    "accept": ["accept"],
    "ioctl": ["ioctlsocket", "ioctl"],
    "getpeername": ["getpeername"],
    "sleep": ["Sleep", "sleep"],
    "exec": ["WinExec", "CreateProcessW", "CreateProcessAsUserW", "popen", "system"],
    "fopen": ["CreateFileW", "fopen", "open"],
    "close": ["CloseHandle", "closesocket", "fclose", "pclose", "close"],
    "fseek": ["SetFilePointer", "fseek"],
    "fsize": ["GetFileSize", "ftell", "stat"],
    "unlink": ["DeleteFileW", "remove"],
    "listdir": ["FindFirstFileW", "FindNextFileW", "FindClose", "scandir"],
    "chdir": ["SetCurrentDirectoryW", "chdir"],
    "getcwd": ["GetCurrentDirectoryW", "getcwd"],
    "user": ["GetUserNameW", "getlogin"],
    "localtime": ["GetLocalTime", "localtime_r"],
    "time": ["GetTickCount", "time"],
    "exists": ["GetFileAttributesW", "access"],
    "pid": ["GetCurrentProcess", "getpid"],
    "rand": ["srand48", "lrand48", "rand", "srand"],
    "exit": ["ExitProcess", "exit"],
    "filetime": ["GetFileTime", "SetFileTime", "FileTimeToLocalFileTime"],
}
NAME_TO_CONCEPT = {n: c for c, names in CONCEPTS.items() for n in names}


def concept(name):
    name = name.split("!")[-1]
    return NAME_TO_CONCEPT.get(name)


def elf_plt(path_or_bin, stub_size=12, header=20):
    b = lief.parse(path_or_bin) if not isinstance(path_or_bin, lief.Binary) else path_or_bin
    plt = b.get_section(".plt")
    return {plt.virtual_address + header + stub_size * i: r.symbol.name for i, r in enumerate(b.pltgot_relocations)}


def thumb_veneers(b, imports):
    """Thumb-to-ARM veneers into the PLT, keyed by the address Thumb callers branch to.

    A veneer is `bx pc` (padded to the next word), then an ARM `b` to the PLT entry. Callers
    name the veneer, never the PLT entry, so without this map no Thumb call reaches an import."""
    text = b.get_section(".text")
    data = bytes(text.content)
    base = text.virtual_address
    out = {}
    for offset in range(0, len(data) - 2, 2):
        if data[offset : offset + 2] != b"\x78\x47":
            continue
        arm = ((base + offset + 4) & ~3) - base
        if arm + 4 > len(data):
            continue
        word = int.from_bytes(data[arm : arm + 4], "little")
        if word & 0xFF000000 != 0xEA000000:
            continue
        imm = word & 0x00FFFFFF
        target = base + arm + 8 + ((imm - (1 << 24) if imm & 0x800000 else imm) << 2)
        if target in imports:
            out[base + offset] = imports[target]
    return out


def pe_iat(b):
    out = {}
    ib = b.optional_header.imagebase
    for lib in b.imports:
        for e in lib.entries:
            if e.name:
                out[ib + e.iat_address] = e.name
    return out
