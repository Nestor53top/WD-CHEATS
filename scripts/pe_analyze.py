#!/usr/bin/env python3
import struct, sys, re, os

def analyze_pe(exe_path):
    f = open(exe_path, 'rb')
    data = f.read()
    f.close()

    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        print("Not a valid PE file")
        return

    machine = struct.unpack_from('<H', data, pe_off+4)[0]
    num_sec = struct.unpack_from('<H', data, pe_off+6)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]
    is64 = magic == 0x20B

    mstr = {0x14c:'x86', 0x8664:'x86-64', 0xAA64:'ARM64'}.get(machine, f'0x{machine:04x}')
    typ = 'PE32+' if is64 else 'PE32'

    print(f"File size: {len(data)} bytes ({len(data)/1024:.1f} KB)")
    print(f"Type: {typ} {mstr}")
    print(f"Sections: {num_sec}")

    # Sections
    sec_off = opt_off + (240 if is64 else 224)
    print("\n--- Sections ---")
    for i in range(num_sec):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        nm = data[o:o+8].split(b'\x00')[0].decode('ascii', 'replace')
        vs = struct.unpack_from('<I', data, o+8)[0]
        va = struct.unpack_from('<I', data, o+12)[0]
        rs = struct.unpack_from('<I', data, o+16)[0]
        ch = struct.unpack_from('<I', data, o+36)[0]
        print(f"  {nm}: VirtSize=0x{vs:08X} VirtAddr=0x{va:08X} RawSize=0x{rs:08X} Chars=0x{ch:08X}")

    # Strings
    text = data.decode('ascii', errors='replace')

    print("\n--- ASCII strings >= 6 chars ---")
    ascii_strs = []
    cur = ''
    for b in data:
        if 32 <= b < 127:
            cur += chr(b)
        else:
            if len(cur) >= 6:
                ascii_strs.append(cur)
            cur = ''
    print(f"Count: {len(ascii_strs)}")

    print("\n--- Unicode strings >= 6 chars ---")
    uni_strs = []
    cur = ''
    for i in range(0, len(data)-1, 2):
        w = struct.unpack_from('<H', data, i)[0]
        if 32 <= w < 127:
            cur += chr(w)
        else:
            if len(cur) >= 6:
                uni_strs.append(cur)
            cur = ''
    print(f"Count: {len(uni_strs)}")

    # DLL imports
    dlls = ['kernel32.dll','user32.dll','advapi32.dll','ntdll.dll','ole32.dll','comctl32.dll',
            'gdi32.dll','shell32.dll','msvcrt.dll','ws2_32.dll','wininet.dll','crypt32.dll',
            'winmm.dll','oleaut32.dll','setupapi.dll','dbghelp.dll','Rpcrt4.dll','wldap32.dll',
            'shlwapi.dll','userenv.dll','uxtheme.dll','dwmapi.dll','dwrite.dll','d2d1.dll',
            'wtsapi32.dll','powrprof.dll','dxgi.dll','bcrypt.dll','ncrypt.dll','iphlpapi.dll',
            'winhttp.dll','mswsock.dll','wshtcpip.dll','version.dll','comdlg32.dll','netapi32.dll',
            'psapi.dll','secur32.dll','mpr.dll','imm32.dll','propsys.dll','cfgmgr32.dll']
    tl = text.lower()
    found = [d for d in dlls if d in tl]
    all_refs = sorted(set(m.lower() for m in re.findall(r'[a-zA-Z0-9_-]+\.dll', text)))
    print(f"\n--- DLL imports ({len(found)}) ---")
    for d in found:
        print(f"  {d}")
    print(f"\n--- All .dll refs ({len(all_refs)}) ---")
    for d in all_refs:
        print(f"  {d}")

    # Language detection
    print("\n--- Language detection ---")
    checks = {
        'Delphi VCL': r'TForm|TButton|TLabel|TEdit|TComboBox',
        'Delphi RTL': r'@Sysutils@|@Classes@|@Forms@|@Controls@',
        'Borland/Delphi': r'Borland|Embarcadero|CodeGear|Delphi',
        'FreePascal/Lazarus': r'FreePascal|FPC|Lazarus',
        'Qt': r'Qt4|Qt5|QtCore|QtGui|QWidget',
        'MFC': r'CWinApp|CWnd|AfxInit|MFC',
        'ImGui': r'ImGui|imgui|IMGUI',
        'C++ MSVC': r'Microsoft Visual C\+\+|MSVC|VisualC',
    }
    for name, pat in checks.items():
        ms = re.findall(pat, text, re.IGNORECASE)
        if ms:
            uniq = list(set(ms))[:10]
            print(f"  FOUND {name} ({len(ms)}): {uniq}")

    # Interesting strings
    print("\n--- Interesting strings ---")
    cats = {
        'TRAINER': r'(?i)(trainer|cheat|hack|mod)',
        'MEMORY': r'(?i)(readprocessmemory|writeprocessmemory|virtualalloc|openprocess)',
        'GAME': r'(?i)(watch.?dogs|wd2|ubisoft|uplay)',
        'FEATURE': r'(?i)(health|ammo|money|speed|god|infinite|noclip|teleport|unlimited|invincib)',
        'KEYBIND': r'(?i)(hotkey|keybind)',
        'PROCESS': r'(?i)(findwindow|enumerateprocess|processid|threadid)',
    }
    for cat, pat in cats.items():
        ms = re.findall(pat, text)
        if ms:
            uniq = list(set(ms))[:5]
            print(f"  [{cat}] {len(ms)}: {uniq}")

    # Version info
    print("\n--- Version info ---")
    for m in re.finditer(r'(?i)(FileVersion|ProductVersion|CompanyName|FileDescription|ProductName|LegalCopyright)[\x00-\x1F]{1,80}([^\x00-\x1F]{2,80})', text):
        print(f"  {m.group(1)}: {m.group(2).strip()}")

    # Hex dump first 512 bytes
    print("\n--- First 512 bytes hex ---")
    for i in range(0, min(512, len(data)), 16):
        hex_part = ' '.join(f'{data[i+j]:02X}' for j in range(16) if i+j < len(data))
        ascii_part = ''.join(chr(data[i+j]) if 32 <= data[i+j] < 127 else '.' for j in range(16) if i+j < len(data))
        print(f"  {i:04X}: {hex_part:<48s} {ascii_part}")

if __name__ == '__main__':
    analyze_pe(sys.argv[1])
