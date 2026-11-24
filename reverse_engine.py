import importlib.util
import hashlib
import io
import marshal
import os
import re
import struct
import zipfile
import zlib

MAX_ZIP_TOTAL = 1024 * 1024 * 1024   # limite de segurança ao abrir ZIPs embutidos
MAX_ZIP_FILES = 5000


# ----------------------------------------------------------------------------
# Escrita segura (impede "../" e caminhos absolutos dentro dos nomes)
# ----------------------------------------------------------------------------
def _clean(part):
    return re.sub(r'[<>:"|?*\x00-\x1f]', "_", part).strip() or "_"


def safe_path(base, rel):
    parts = [_clean(p) for p in str(rel).replace("\\", "/").split("/") if p not in ("", ".", "..")]
    if not parts:
        parts = ["sem_nome"]
    path = os.path.join(base, *parts)
    ab = os.path.abspath(base)
    if os.path.commonpath([ab, os.path.abspath(path)]) != ab:
        raise ValueError("caminho inseguro: " + str(rel))
    return path


def write_file(base, rel, data):
    path = safe_path(base, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def sha1(data):
    return hashlib.sha1(data).hexdigest()


SNIFF = [
    (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"), (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"), (b"\x00\x00\x01\x00", "ico"), (b"OggS", "ogg"), (b"7z\xbc\xaf", "7z"),
    (b"\x1f\x8b", "gz"), (b"SQLite format 3", "sqlite"), (b"<?xml", "xml"), (b"{\\rtf", "rtf"),
    (b"MZ", "exe"), (b"\x7fELF", "elf"),
]


def sniff(data):
    if data.startswith(b"RIFF") and len(data) > 12:
        return {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(data[8:12], "riff")
    for sig, ext in SNIFF:
        if data.startswith(sig):
            return ext
    head = data[:200]
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head):
        return "txt"
    return "bin"


# ----------------------------------------------------------------------------
# 1) Recursos do Windows (.rsrc)
# ----------------------------------------------------------------------------
RT = {1: "cursor", 2: "bitmap", 3: "icon", 4: "menu", 5: "dialog", 6: "string", 9: "accelerator",
      10: "rcdata", 11: "messagetable", 12: "group_cursor", 14: "group_icon", 16: "version",
      23: "html", 24: "manifest"}


def rva_to_off(rva, secs):
    for s in secs:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return rva - s["vaddr"] + s["rptr"]
    return None


def read_resource_tree(d, info):
    """Devolve [(caminho, dados)], onde caminho = [tipo, nome, idioma]."""
    dirs = info.get("dirs", [])
    if len(dirs) <= 2 or not dirs[2][0]:
        return []
    base = rva_to_off(dirs[2][0], info["secs"])
    if base is None:
        return []
    leaves = []

    def label(v):
        if v & 0x80000000:
            o = base + (v & 0x7FFFFFFF)
            n = struct.unpack_from("<H", d, o)[0]
            return d[o + 2:o + 2 + n * 2].decode("utf-16le", "replace")
        return v

    def walk(off, path, depth):
        o = base + off
        nnamed, nid = struct.unpack_from("<HH", d, o + 12)
        for i in range(min(nnamed + nid, 2048)):
            name, target = struct.unpack_from("<II", d, o + 16 + 8 * i)
            lab = label(name)
            if target & 0x80000000:
                if depth < 3 and len(leaves) < 5000:
                    walk(target & 0x7FFFFFFF, path + [lab], depth + 1)
            else:
                rva, size, _cp, _ = struct.unpack_from("<IIII", d, base + target)
                po = rva_to_off(rva, info["secs"])
                if po is not None and size < len(d):
                    leaves.append((path + [lab], d[po:po + size]))

    try:
        walk(0, [], 0)
    except (struct.error, IndexError, RecursionError):
        pass
    return leaves


def build_ico(group, icons):
    count = struct.unpack_from("<H", group, 4)[0]
    entries, blobs = [], []
    offset = 6 + 16 * count
    for i in range(count):
        w, h, colors, _r, planes, bits, size, icon_id = struct.unpack_from("<BBBBHHIH", group, 6 + 14 * i)
        blob = icons.get(icon_id)
        if blob is None:
            continue
        entries.append(struct.pack("<BBBBHHII", w, h, colors, 0, planes, bits, len(blob), offset))
        blobs.append(blob)
        offset += len(blob)
    if not entries:
        return None
    return struct.pack("<HHH", 0, 1, len(entries)) + b"".join(entries) + b"".join(blobs)


def dib_to_bmp(dib):
    if len(dib) < 40:
        return None
    hdr = struct.unpack_from("<I", dib, 0)[0]
    bits = struct.unpack_from("<H", dib, 14)[0]
    used = struct.unpack_from("<I", dib, 32)[0]
    palette = (used or (1 << bits)) * 4 if bits <= 8 else 0
    return b"BM" + struct.pack("<IHHI", 14 + len(dib), 0, 0, 14 + hdr + palette) + dib


def extract_pe_resources(d, info, outdir, seen=None):
    leaves = read_resource_tree(d, info)
    written, icons, groups, strings = [], {}, [], []
    for path, data in leaves:
        rtype = path[0]
        tname = RT.get(rtype, str(rtype)) if isinstance(rtype, int) else rtype
        rname = path[1] if len(path) > 1 else "0"
        if seen is not None:
            seen.add(sha1(data))
        if tname == "icon":
            icons[rname] = data
        elif tname == "group_icon":
            groups.append((rname, data))
        elif tname == "bitmap":
            bmp = dib_to_bmp(data)
            if bmp:
                written.append(write_file(outdir, f"imagens/bitmap_{rname}.bmp", bmp))
        elif tname == "manifest":
            written.append(write_file(outdir, "manifest.xml", data))
        elif tname == "html":
            written.append(write_file(outdir, f"html/{rname}.html", data))
        elif tname == "string":
            if isinstance(rname, int):
                off = 0
                for i in range(16):
                    if off + 2 > len(data):
                        break
                    n = struct.unpack_from("<H", data, off)[0]
                    txt = data[off + 2:off + 2 + 2 * n].decode("utf-16le", "replace")
                    off += 2 + 2 * n
                    if n:
                        strings.append(((rname - 1) * 16 + i, txt))
        elif tname == "version":
            parts = re.findall(rb"(?:[\x20-\x7e]\x00){2,}", data)
            text = "\n".join(p.decode("utf-16le") for p in parts)
            written.append(write_file(outdir, "versao.txt", text.encode("utf-8")))
        elif tname in ("rcdata", "messagetable", "menu", "dialog", "accelerator"):
            ext = sniff(data)
            written.append(write_file(outdir, f"{tname}/{rname}.{ext}", data))
        # cursores são ignorados de propósito
    for rname, group in groups:
        try:
            ico = build_ico(group, {int(k): v for k, v in icons.items() if isinstance(k, int)})
        except struct.error:
            ico = None
        if ico:
            written.append(write_file(outdir, f"icones/icone_{rname}.ico", ico))
    if strings:
        txt = "\n".join(f"{i}: {s}" for i, s in sorted(strings))
        written.append(write_file(outdir, "textos.txt", txt.encode("utf-8")))
    return written


# ----------------------------------------------------------------------------
# 2) Arquivos embutidos ("carving" por assinatura)
# ----------------------------------------------------------------------------
def png_end(d, s):
    pos, n = s + 8, len(d)
    while pos + 12 <= n:
        ln, typ = struct.unpack_from(">I4s", d, pos)
        pos += 12 + ln
        if pos > n:
            return None
        if typ == b"IEND":
            return pos
    return None


def jpeg_end(d, s):
    i, n = s + 2, len(d)
    while i + 4 <= n:
        if d[i] != 0xFF:
            return None
        m = d[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            return i + 2
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        ln = struct.unpack_from(">H", d, i + 2)[0]
        if ln < 2:
            return None
        i += 2 + ln
        if m == 0xDA:   # dados comprimidos: andar até o próximo marcador de verdade
            while True:
                j = d.find(b"\xff", i)
                if j == -1 or j + 1 >= n:
                    return None
                nb = d[j + 1]
                if nb == 0x00 or 0xD0 <= nb <= 0xD7:
                    i = j + 2
                    continue
                i = j
                break
    return None


def _skip_sub(d, i):
    n = len(d)
    while i < n:
        ln = d[i]
        i += 1
        if ln == 0:
            return i
        i += ln
    return None


def gif_end(d, s):
    n = len(d)
    if s + 13 > n:
        return None
    flags = d[s + 10]
    i = s + 13
    if flags & 0x80:
        i += 3 * (2 ** ((flags & 7) + 1))
    while i < n:
        b = d[i]
        if b == 0x3B:
            return i + 1
        if b == 0x21:
            i = _skip_sub(d, i + 2)
        elif b == 0x2C:
            if i + 10 > n:
                return None
            f = d[i + 9]
            i += 10
            if f & 0x80:
                i += 3 * (2 ** ((f & 7) + 1))
            i = _skip_sub(d, i + 1)
        else:
            return None
        if i is None:
            return None
    return None


def zip_end(d, s):
    pos, first = s, None
    for _ in range(200):
        e = d.find(b"PK\x05\x06", pos)
        if e == -1 or e + 22 > len(d):
            break
        cd_size, cd_off = struct.unpack_from("<II", d, e + 12)
        end = e + 22 + struct.unpack_from("<H", d, e + 20)[0]
        if first is None:
            first = end
        if e - cd_size - cd_off == s:
            return end
        pos = e + 4
    return first


def riff_end(d, s):
    size = struct.unpack_from("<I", d, s + 4)[0]
    end = s + 8 + size
    return end if size >= 4 and end <= len(d) else None


def sevenz_end(d, s):
    if s + 32 > len(d):
        return None
    off, size = struct.unpack_from("<QQ", d, s + 12)
    end = s + 32 + off + size
    return end if end <= len(d) else None


def sqlite_end(d, s):
    if s + 32 > len(d):
        return None
    ps = struct.unpack_from(">H", d, s + 16)[0]
    ps = 65536 if ps == 1 else ps
    pages = struct.unpack_from(">I", d, s + 28)[0]
    if ps < 512 or ps & (ps - 1) or not pages:
        return None
    end = s + ps * pages
    return end if end <= len(d) else None


def pdf_end(d, s):
    e = d.find(b"%%EOF", s)
    return e + 5 if e != -1 else None


CARVE_RE = re.compile(
    b"\x89PNG\r\n\x1a\n|\xff\xd8\xff[\xe0\xe1\xdb\xee]|GIF8[79]a|PK\x03\x04|"
    b"RIFF.{4}(?:WAVE|AVI |WEBP)|%PDF-|7z\xbc\xaf\x27\x1c|SQLite format 3\x00", re.S)


def carve(d, outdir, seen=None, max_files=500, min_size=64):
    """Procura arquivos conhecidos escondidos dentro do binário e salva cada um."""
    found, last_end = [], 0
    for m in CARVE_RE.finditer(d):
        s = m.start()
        if s < last_end or len(found) >= max_files:
            continue
        sig = m.group()
        try:
            if sig.startswith(b"\x89PNG"):
                kind, end = "png", png_end(d, s)
            elif sig.startswith(b"\xff\xd8"):
                kind, end = "jpg", jpeg_end(d, s)
            elif sig.startswith(b"GIF"):
                kind, end = "gif", gif_end(d, s)
            elif sig.startswith(b"PK"):
                kind, end = "zip", zip_end(d, s)
            elif sig.startswith(b"RIFF"):
                kind, end = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}[sig[8:12]], riff_end(d, s)
            elif sig.startswith(b"%PDF"):
                kind, end = "pdf", pdf_end(d, s)
            elif sig.startswith(b"7z"):
                kind, end = "7z", sevenz_end(d, s)
            else:
                kind, end = "sqlite", sqlite_end(d, s)
        except (struct.error, KeyError):
            continue
        if not end or end - s < min_size or (s == 0 and end == len(d)):
            continue
        blob = d[s:end]
        h = sha1(blob)
        last_end = end
        if seen is not None:
            if h in seen:
                continue
            seen.add(h)
        path = write_file(outdir, f"{s:08x}.{kind}", blob)
        entry = {"offset": s, "tipo": kind, "tamanho": len(blob), "arquivo": path}
        if kind == "zip":
            entry["conteudo"] = unpack_zip(blob, path + "_conteudo")
        found.append(entry)
    return found


def unpack_zip(blob, dest):
    """Abre um ZIP/JAR embutido com limites de segurança. Devolve lista de nomes."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_FILES or sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
            return [f"(muito grande para abrir: {len(infos)} itens)"]
        names = []
        for i in infos:
            if i.is_dir():
                continue
            write_file(dest, i.filename, zf.read(i))
            names.append(i.filename)
        return names
    except (zipfile.BadZipFile, ValueError, RuntimeError, OSError):
        return []


# ----------------------------------------------------------------------------
# 3) PyInstaller
# ----------------------------------------------------------------------------
PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def pyc_header(magic, major, minor):
    if major == 3 and minor >= 7:
        return magic + b"\0" * 12
    if major == 3 and minor >= 3:
        return magic + b"\0" * 8
    return magic + b"\0" * 4


def _unzip_entry(blob, compressed):
    return zlib.decompress(blob) if compressed else blob


def parse_pyinstaller(d):
    pos = d.rfind(PYI_MAGIC)
    if pos == -1:
        return None
    new = b"python" in d[pos + 24:pos + 88].lower()
    try:
        if new:
            _m, length, toc, toclen, pyver, _lib = struct.unpack_from("!8sIIii64s", d, pos)
            cookie = 88
        else:
            _m, length, toc, toclen, pyver = struct.unpack_from("!8siiii", d, pos)
            cookie = 24
    except struct.error:
        return None
    tail = len(d) - (pos + cookie)
    overlay = len(d) - (length + tail)
    if overlay < 0 or toclen <= 0 or toclen > len(d):
        return None
    major, minor = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
    entries, p = [], overlay + toc
    end = p + toclen
    try:
        while p < end:
            esize, epos, csize, usize, cflag, ctype = struct.unpack_from("!iiiiBc", d, p)
            if esize <= 18:
                break
            name = d[p + 18:p + esize].split(b"\0", 1)[0].decode("utf-8", "replace")
            entries.append(dict(name=name, pos=overlay + epos, csize=csize, usize=usize,
                                comp=bool(cflag), type=ctype))
            p += esize
    except struct.error:
        return None
    return dict(version=("2.1+" if new else "2.0"), pyver=(major, minor), entries=entries)


def extract_pyz(data, outdir, header):
    """Abre um arquivo PYZ do PyInstaller e grava cada módulo como .pyc."""
    if data[:4] != b"PYZ\0":
        return 0
    toc_off = struct.unpack_from("!i", data, 8)[0]
    toc = marshal.loads(data[toc_off:])
    if isinstance(toc, list):
        toc = dict(toc)
    count = 0
    for name, (ispkg, pos, length) in toc.items():
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        try:
            code = zlib.decompress(data[pos:pos + length])
        except zlib.error:
            continue   # provavelmente criptografado
        rel = name.replace(".", "/") + ("/__init__" if ispkg else "") + ".pyc"
        write_file(outdir, rel, header + code)
        count += 1
    return count


def extract_pyinstaller(d, outdir):
    info = parse_pyinstaller(d)
    if not info:
        return None
    major, minor = info["pyver"]
    magic = importlib.util.MAGIC_NUMBER
    pyz_blobs = []
    for e in info["entries"]:
        if e["type"] in (b"z", b"Z"):
            try:
                blob = _unzip_entry(d[e["pos"]:e["pos"] + e["csize"]], e["comp"])
                if blob[:4] == b"PYZ\0":
                    magic = blob[4:8]
                pyz_blobs.append((e["name"], blob))
            except zlib.error:
                pass
    header = pyc_header(magic, major, minor)
    files, scripts, modules = [], [], 0
    for e in info["entries"]:
        if e["type"] in (b"z", b"Z") or e["type"] == b"o":
            continue
        try:
            blob = _unzip_entry(d[e["pos"]:e["pos"] + e["csize"]], e["comp"])
        except zlib.error:
            continue
        name = e["name"]
        if e["type"] in (b"s", b"m", b"M"):
            if blob[2:4] != b"\r\n":
                blob = header + blob
            if not name.endswith(".pyc"):
                name += ".pyc"
            if e["type"] == b"s" and not name.startswith("pyi"):
                scripts.append(name)
        files.append(write_file(outdir, name, blob))
    for name, blob in pyz_blobs:
        modules += extract_pyz(blob, os.path.join(outdir, name + "_modulos"), header)
    return dict(version=info["version"], python=f"{major}.{minor}", arquivos=len(files),
                modulos=modules, scripts=scripts)


# ----------------------------------------------------------------------------
# 4) Qual tecnologia é? E qual ferramenta open source usar?
# ----------------------------------------------------------------------------
def detect_tech(d, info, has_pyi):
    techs = []

    def add(nome, dica):
        techs.append((nome, dica))

    if has_pyi:
        add("Python + PyInstaller",
            "Este extrator já tirou os .pyc. Para virar .py use pycdc (Decompyle++) ou, "
            "em Python até 3.8, uncompyle6/decompyle3 (pip install uncompyle6).")
    if info and len(info.get("dirs", [])) > 14 and info["dirs"][14][0]:
        add(".NET (C#/VB)", "Abra no ILSpy (open source, MIT) ou use 'ilspycmd arquivo.exe -p -o pasta' "
                            "para obter o código C# quase igual ao original.")
    if re.search(rb"(?i)py2exe", d):
        add("py2exe", "Procure o library.zip ao lado do .exe: dentro estão os .pyc.")
    if re.search(rb"(?i)nuitka", d):
        add("Nuitka", "Compila Python para C: o .py original NÃO volta. Use o Ghidra.")
    if re.search(rb"app\.asar", d):
        add("Electron (JavaScript)", "Código em app.asar: 'npx asar extract app.asar pasta' dá o JS legível.")
    if re.search(rb"(?i)launch4j|META-INF/MANIFEST\.MF", d):
        add("Java (jar embutido)", "O .jar sai em 'embutidos/'. Decompile com CFR, Procyon ou Fernflower.")
    if re.search(rb"Nullsoft", d):
        add("Instalador NSIS", "O 7-Zip abre direto e mostra os arquivos instalados.")
    if re.search(rb"Inno Setup Setup Data", d):
        add("Instalador Inno Setup", "Use o innoextract (open source) para extrair os arquivos.")
    if re.search(rb"UnityPlayer|UnityEngine", d):
        add("Unity", "Os assets ficam na pasta *_Data, não no .exe. Use o AssetRipper (open source).")
    if re.search(rb"Go build ID|runtime\.gopanic", d):
        add("Go", "Binário nativo: use o Ghidra (com GoReSym para recuperar nomes de funções).")
    if re.search(rb"/rustc/", d):
        add("Rust", "Binário nativo: use o Ghidra ou o Cutter.")
    if not techs:
        add("Nativo (C/C++/Delphi...)",
            "O código-fonte não está no arquivo. Para ver o programa por dentro use o Ghidra "
            "(open source, com decompilador) ou o Cutter/rizin.")
    return techs


# ----------------------------------------------------------------------------
# Orquestrador
# ----------------------------------------------------------------------------
def extract_all(data, info, outdir, log=print):
    os.makedirs(outdir, exist_ok=True)
    seen = set()
    rep = dict(recursos=[], embutidos=[], pyinstaller=None, tecnologias=[])

    if info and info.get("dirs"):
        log("Lendo recursos do Windows (.rsrc)...")
        rep["recursos"] = extract_pe_resources(data, info, os.path.join(outdir, "recursos"), seen)
        log(f"  {len(rep['recursos'])} item(ns) de recurso salvos")

    log("Procurando arquivos embutidos (PNG, JPG, ZIP, WAV...)...")
    rep["embutidos"] = carve(data, os.path.join(outdir, "embutidos"), seen)
    log(f"  {len(rep['embutidos'])} arquivo(s) encontrados")

    log("Procurando pacote PyInstaller...")
    try:
        rep["pyinstaller"] = extract_pyinstaller(data, os.path.join(outdir, "pyinstaller"))
    except Exception as exc:   # formato com variação inesperada: não derruba o resto
        log(f"  falha ao ler o PyInstaller: {exc}")
    py = rep["pyinstaller"]
    if py:
        log(f"  PyInstaller {py['version']} · Python {py['python']} · "
            f"{py['arquivos']} arquivos, {py['modulos']} módulos")
    else:
        log("  não é PyInstaller")

    rep["tecnologias"] = detect_tech(data, info, bool(py))
    write_file(outdir, "LEIAME.txt", build_readme(rep).encode("utf-8"))
    return rep


def build_readme(rep):
    L = ["REVERSE LAB - resultado da extração", "=" * 36, ""]
    L.append("Tecnologia provável e o que fazer a seguir:")
    for nome, dica in rep["tecnologias"]:
        L.append(f"  * {nome}\n      {dica}")
    L += ["", f"recursos/    : {len(rep['recursos'])} item(ns) (ícones .ico, imagens, manifest, textos)",
          f"embutidos/   : {len(rep['embutidos'])} arquivo(s) achados por assinatura"]
    for e in rep["embutidos"][:100]:
        extra = f"  ({len(e['conteudo'])} itens dentro)" if e.get("conteudo") else ""
        L.append(f"    0x{e['offset']:08x}  {e['tipo']:<6}{e['tamanho']:>10} bytes{extra}")
    py = rep["pyinstaller"]
    if py:
        L += ["", f"pyinstaller/ : Python {py['python']}, {py['arquivos']} arquivos, {py['modulos']} módulos"]
        if py["scripts"]:
            L.append("    scripts do programa (provável código principal): " + ", ".join(py["scripts"]))
    L += ["", "Use só em programas seus, open source ou com permissão do autor.",
          "Assets e código de software comercial costumam ter direitos autorais."]
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------
# 5) Leitor mínimo de PE (gera o "info" usado pelo resto do módulo)
# ----------------------------------------------------------------------------
def parse_pe(d):
    """Lê o cabeçalho PE. Devolve {'secs': [...], 'dirs': [(rva, size), ...]} ou None."""
    try:
        if len(d) < 64 or d[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            return None
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsize = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x10B:      # PE32
            dd = opt + 96
        elif magic == 0x20B:    # PE32+
            dd = opt + 112
        else:
            return None
        ndirs = min(struct.unpack_from("<I", d, dd - 4)[0], 16)
        dirs = [struct.unpack_from("<II", d, dd + 8 * i) for i in range(ndirs)]
        secs = []
        so = opt + optsize
        for i in range(min(nsec, 96)):
            _n, vsize, vaddr, rsize, rptr = struct.unpack_from("<8sIIII", d, so + 40 * i)
            secs.append(dict(vsize=vsize, vaddr=vaddr, rsize=rsize, rptr=rptr))
        return dict(secs=secs, dirs=dirs, pe64=(magic == 0x20B))
    except struct.error:
        return None


# ----------------------------------------------------------------------------
# 6) Ferramentas externas: instalar, desinstalar e localizar
#    Tudo vai para UMA pasta (sem precisar de administrador). Desinstalar = apagar a pasta.
#    Nenhuma ferramenta EXECUTA o programa analisado: só leem o arquivo.
# ----------------------------------------------------------------------------
import json
import shutil
import stat
import subprocess
import sys
import urllib.request

IS_WIN = sys.platform.startswith("win")
TOOLS_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                         "ReverseLab", "ferramentas")

NOMES = {"ghidra": "Ghidra (decompilador)", "rizin": "rizin (assembly/info)",
         "cutter": "Cutter (interface gráfica do rizin)", "jdk": "JDK 21 portátil (Java, exigido pelo Ghidra)"}
ORDEM = ["ghidra", "rizin", "cutter", "jdk"]


def _http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ReverseLab",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _github_asset(repo, score):
    """Pega o arquivo da última versão cujo nome tem a maior pontuação (score(nome_minusculo) > 0)."""
    j = _http_json(f"https://api.github.com/repos/{repo}/releases/latest")
    best = None
    for a in j.get("assets", []):
        s = score(a["name"].lower())
        if s > 0 and (best is None or s > best[0]):
            best = (s, a)
    if not best:
        raise RuntimeError(j.get("message") or "nenhum arquivo para Windows encontrado na última versão")
    a = best[1]
    sha = (a.get("digest") or "").replace("sha256:", "") or None
    return dict(nome=a["name"], url=a["browser_download_url"], sha256=sha,
                size=a.get("size", 0), versao=j.get("tag_name", ""))


def _resolve_ghidra():
    return _github_asset("NationalSecurityAgency/ghidra",
                         lambda n: 1 if n.startswith("ghidra_") and n.endswith(".zip") else 0)


def _resolve_rizin():
    def sc(n):
        if not (n.endswith(".zip") and "windows" in n):
            return 0
        return 2 if "shared64" in n else 1
    return _github_asset("rizinorg/rizin", sc)


def _resolve_cutter():
    return _github_asset("rizinorg/cutter",
                         lambda n: 1 if n.endswith(".zip") and "windows" in n and "x86_64" in n else 0)


def _resolve_jdk():
    try:
        j = _http_json("https://api.adoptium.net/v3/assets/latest/21/hotspot"
                       "?architecture=x64&image_type=jdk&os=windows")
        pkg = j[0]["binary"]["package"]
        return dict(nome=pkg["name"], url=pkg["link"], sha256=pkg.get("checksum"),
                    size=pkg.get("size", 0), versao="21")
    except Exception:
        return dict(nome="jdk21.zip", sha256=None, size=0, versao="21",
                    url="https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse")


RESOLVERS = {"ghidra": _resolve_ghidra, "rizin": _resolve_rizin,
             "cutter": _resolve_cutter, "jdk": _resolve_jdk}


def _download(url, dest, sha256=None):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": "ReverseLab"})
    with urllib.request.urlopen(req, timeout=60) as r, open(part, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        got = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            h.update(chunk)
            got += len(chunk)
            _progress("baixando", got, total)
    print()
    if sha256 and h.hexdigest().lower() != sha256.lower():
        os.remove(part)
        raise RuntimeError("o arquivo baixado está corrompido (checksum não confere)")
    os.replace(part, dest)


def _extract_zip(zpath, dest):
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(zpath) as zf:
        infos = zf.infolist()
        for n, info in enumerate(infos, 1):
            path = safe_path(dest, info.filename)   # bloqueia "../"
            if info.is_dir():
                os.makedirs(path, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with zf.open(info) as src, open(path, "wb") as out:
                shutil.copyfileobj(src, out)
            if n % 100 == 0:
                _progress("extraindo", n, len(infos), mb=False)
    _progress("extraindo", 1, 1, mb=False)
    print()


def _rmtree(path):
    ab_tools, ab = os.path.abspath(TOOLS_DIR), os.path.abspath(path)
    if os.path.commonpath([ab_tools, ab]) != ab_tools or ab == ab_tools:
        raise ValueError("recusei apagar fora da pasta de ferramentas: " + path)

    def onerr(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(ab, onerror=onerr)


def _find_file(root, names):
    names = {n.lower() for n in names}
    if not os.path.isdir(root):
        return None
    for folder, _dirs, files in os.walk(root):
        for f in files:
            if f.lower() in names:
                return os.path.join(folder, f)
    return None


def find_java_home():
    exe = _find_file(os.path.join(TOOLS_DIR, "jdk"), {"java.exe", "java"})
    return os.path.dirname(os.path.dirname(exe)) if exe else None


def find_ghidra(ghidra_dir=None):
    name = "analyzeHeadless.bat" if IS_WIN else "analyzeHeadless"
    for r in (ghidra_dir, os.environ.get("GHIDRA_HOME")):
        if r:
            hit = _find_file(r, {name})
            if hit:
                return hit
    return (_find_file(os.path.join(TOOLS_DIR, "ghidra"), {name})
            or shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat"))


def find_rizin(path=None):
    for c in (path, os.environ.get("RIZIN_PATH")):
        if c and os.path.isfile(c):
            return c
    return _find_file(os.path.join(TOOLS_DIR, "rizin"), {"rizin.exe", "rizin"}) or shutil.which("rizin")


def find_cutter(path=None):
    for c in (path, os.environ.get("CUTTER_PATH")):
        if c and os.path.isfile(c):
            return c
    return (_find_file(os.path.join(TOOLS_DIR, "cutter"), {"cutter.exe", "cutter"})
            or shutil.which("cutter") or shutil.which("Cutter"))


FINDERS = {"ghidra": find_ghidra, "rizin": find_rizin, "cutter": find_cutter, "jdk": find_java_home}


def _dir_size_mb(path):
    total = 0
    for folder, _d, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(folder, f))
            except OSError:
                pass
    return total / 1e6


def install_tool(key, ask=True, log=print):
    """Baixa a última versão oficial e instala na pasta de ferramentas. Devolve True se deu certo."""
    if not IS_WIN:
        log("  A instalação automática é só para Windows. No Linux/Mac use o gerenciador de pacotes "
            "(apt, brew...) ou baixe pelos sites: ghidra-sre.org, rizin.re, cutter.re.")
        return False
    if key == "ghidra" and not find_java_home():
        log("  O Ghidra precisa do Java (JDK 21). Vou instalar um JDK portátil junto.")
        if not install_tool("jdk", ask, log):
            return False
    log(f"Procurando a versão mais recente de {NOMES[key]}...")
    try:
        meta = RESOLVERS[key]()
    except Exception as exc:
        log(f"  não consegui consultar o site ({exc}). Tente de novo mais tarde.")
        return False
    mb = f"{meta['size'] / 1e6:.0f} MB" if meta["size"] else "tamanho desconhecido"
    log(f"  versão {meta['versao']} · {meta['nome']} · {mb}")
    if ask:
        if input("  Baixar e instalar? [S/n] ").strip().lower() in ("n", "nao", "não"):
            return False
    dest = os.path.join(TOOLS_DIR, key)
    zpath = os.path.join(TOOLS_DIR, "_downloads", meta["nome"])
    try:
        _download(meta["url"], zpath, meta["sha256"])
        if os.path.isdir(dest):
            _rmtree(dest)
        _extract_zip(zpath, dest)
    except Exception as exc:
        log(f"  falhou: {exc}")
        if os.path.isdir(dest):
            _rmtree(dest)
        return False
    finally:
        if os.path.isfile(zpath):
            os.remove(zpath)
    if FINDERS[key]():
        log(f"  OK: {NOMES[key]} instalado em {dest}")
        return True
    log("  A extração terminou, mas não achei o executável. A estrutura do pacote pode ter mudado.")
    return False


def uninstall_tool(key, ask=True, log=print):
    dest = os.path.join(TOOLS_DIR, key)
    if not os.path.isdir(dest):
        log(f"  {NOMES[key]}: não foi instalado por este programa (nada para remover).")
        return False
    mb = _dir_size_mb(dest)
    if key == "jdk":
        log("  Atenção: sem o JDK o Ghidra instalado aqui deixa de funcionar.")
    if ask and input(f"  Apagar {NOMES[key]} ({mb:.0f} MB)? [s/N] ").strip().lower() not in ("s", "sim", "y"):
        return False
    try:
        _rmtree(dest)
    except Exception as exc:
        log(f"  falhou ao apagar: {exc}")
        return False
    log(f"  {NOMES[key]} removido.")
    for p in (os.path.join(TOOLS_DIR, "_downloads"), TOOLS_DIR):
        try:
            os.rmdir(p)
        except OSError:
            pass
    return True


# ----------------------------------------------------------------------------
# 7) Ghidra, rizin e Cutter em ação
# ----------------------------------------------------------------------------
GHIDRA_SCRIPT = r'''
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "decompilado.c";
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                w.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " ====");
                if (r.decompileCompleted()) {
                    w.println(r.getDecompiledFunction().getC());
                } else {
                    w.println("// falha: " + r.getErrorMessage());
                }
            }
        }
        ifc.dispose();
    }
}
'''


def run_ghidra(analyze_headless, target, outdir, timeout=1800, log=print):
    """Importa o arquivo no Ghidra (headless) e exporta o código C decompilado."""
    gdir = os.path.join(outdir, "ghidra")
    script_dir = os.path.join(gdir, "_scripts")
    proj_dir = os.path.join(gdir, "_projeto")
    os.makedirs(script_dir, exist_ok=True)
    os.makedirs(proj_dir, exist_ok=True)
    with open(os.path.join(script_dir, "DecompileAll.java"), "w", encoding="utf-8") as f:
        f.write(GHIDRA_SCRIPT)
    out_c = os.path.join(gdir, "decompilado.c")
    env = os.environ.copy()
    jh = find_java_home()
    if jh:
        env["JAVA_HOME"] = jh
        env["PATH"] = os.path.join(jh, "bin") + os.pathsep + env.get("PATH", "")
    cmd = [analyze_headless, proj_dir, "reverse_lab", "-import", os.path.abspath(target),
           "-scriptPath", script_dir, "-postScript", "DecompileAll.java", out_c,
           "-overwrite", "-deleteProject"]
    log("  Ghidra: analisando (pode demorar vários minutos)...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env,
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        log(f"  Ghidra: passou de {timeout}s e foi interrompido")
        return None
    except OSError as exc:
        log(f"  Ghidra: não consegui iniciar ({exc})")
        return None
    with open(os.path.join(gdir, "ghidra_log.txt"), "w", encoding="utf-8") as f:
        f.write(r.stdout + "\n" + r.stderr)
    if os.path.isfile(out_c):
        log(f"  Ghidra: código decompilado em {out_c}")
        return out_c
    log("  Ghidra: não gerou saída. Veja ghidra/ghidra_log.txt")
    return None


RIZIN_JOBS = [
    ("info.txt",        "iI"),
    ("secoes.txt",      "iS"),
    ("imports.txt",     "ii"),
    ("exports.txt",     "iE"),
    ("strings.txt",     "izz"),
    ("funcoes.txt",     "aaa; afl"),
    ("entrada.asm",     "aaa; pdf @ entry0"),
    ("disassembly.asm", "aaa; pdf @@f"),
]


def run_rizin(rizin, target, outdir, timeout=900, log=print):
    rdir = os.path.join(outdir, "rizin")
    os.makedirs(rdir, exist_ok=True)
    done = []
    log("  rizin: extraindo informações e assembly...")
    for fname, cmds in RIZIN_JOBS:
        try:
            r = subprocess.run([rizin, "-q", "-c", cmds, os.path.abspath(target)],
                               capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            log(f"    {fname}: falhou ({exc.__class__.__name__})")
            continue
        if r.stdout.strip():
            write_file(rdir, fname, r.stdout)
            done.append(fname)
    log(f"  rizin: {len(done)} arquivo(s) em {rdir}")
    return done


def open_cutter(cutter, target):
    try:
        subprocess.Popen([cutter, os.path.abspath(target)])
        return True
    except OSError:
        return False


# ----------------------------------------------------------------------------
# 8) Cores e utilidades de tela (estilo Reverse Lab)
# ----------------------------------------------------------------------------
import colorsys
import textwrap
import time

if IS_WIN:
    os.system("")   # ativa cores ANSI no Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ESC = "\033"
RESET = f"{ESC}[0m"


def rgb(r, g, b):
    return f"{ESC}[38;2;{r};{g};{b}m"


DIM = rgb(110, 110, 130)
OK = rgb(80, 250, 123)
ERR = rgb(255, 85, 85)
WARN = rgb(255, 184, 108)
KEY = rgb(139, 233, 253)
VAL = rgb(248, 248, 242)
PURPLE = rgb(189, 147, 249)
PINK = rgb(255, 121, 198)
SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def paint(color, text):
    return f"{color}{text}{RESET}"


def hsv(h, s=1.0, v=1.0):
    r, g, b = colorsys.hsv_to_rgb(h % 1.0, s, v)
    return int(r * 255), int(g * 255), int(b * 255)


def rainbow(text, shift=0.0):
    return paint(PURPLE, text)


def term_size():
    s = shutil.get_terminal_size((100, 30))
    return s.columns, s.lines


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def kv(key, val, w=15):
    return f"  {paint(KEY, f'{key:<{w}}')}{val}"


def title(text):
    return f"\n  {rainbow('━━ ' + text + ' ' + '━' * max(4, 50 - len(text)))}"


def bar(frac, width=24):
    filled = int(max(0.0, min(1.0, frac)) * width)
    return paint(OK, "█" * filled) + paint(DIM, "░" * (width - filled))


def _progress(label, got, total, mb=True):
    """Barra colorida usada nos downloads e extrações."""
    frac = got / total if total else 0.0
    if mb and total:
        info = f"{got / 1e6:5.0f}/{total / 1e6:.0f} MB ({frac * 100:3.0f}%)"
    elif mb:
        info = f"{got / 1e6:.0f} MB"
    else:
        info = f"{frac * 100:3.0f}%"
    spin = SPIN[int(time.time() * 12) % len(SPIN)]
    sys.stdout.write(f"\r  {PURPLE}{spin}{RESET} {label:<11}{bar(frac)} {paint(DIM, info)}   ")
    sys.stdout.flush()


ERRWORDS = ("falhou", "não consegui", "não gerou", "passou de", "não está instalado", "erro", "falha",
            "corrompido", "recusei")


def say(msg):
    """Imprime as mensagens das ferramentas com cor."""
    t = msg.strip()
    low = t.lower()
    if t.startswith("OK"):
        print("  " + paint(OK, "✔ " + t))
    elif "ainda não está instalado" in low or t.startswith("Atenção"):
        print("  " + paint(WARN, "! " + t))
    elif any(w in low for w in ERRWORDS):
        print("  " + paint(ERR, "✖ " + t))
    elif t.startswith("Atenção"):
        print("  " + paint(WARN, "! " + t))
    elif msg.startswith("  "):
        print("    " + paint(DIM, t))
    else:
        print("  " + paint(PURPLE, "▸ ") + paint(KEY, t))


def _log_extracao(msg):
    t = msg.strip()
    if msg.startswith("  "):
        bad = any(w in t.lower() for w in ERRWORDS)
        print("    " + (paint(ERR, "✖ ") if bad else paint(OK, "• ")) + paint(ERR if bad else DIM, t))
    else:
        print("  " + paint(PURPLE, "▸ ") + paint(KEY, t))


FONT = {
    " ": ["   "] * 5,
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "V": ["#   #", "#   #", "#   #", " # # ", "  #  "],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "B": ["#### ", "#   #", "#### ", "#   #", "#### "],
}


def banner(shift=0.0):
    rows = [""] * 5
    for ch in "REVERSE LAB":
        for i in range(5):
            rows[i] += FONT[ch][i].replace("#", "█") + " "
    w = len(rows[0])
    for r, line in enumerate(rows):
        print("  " + paint(PURPLE, line))
    print(paint(DIM, "  extrator + Ghidra · rizin · Cutter · só lê, nunca executa o arquivo\n"))


def pausar():
    try:
        input(paint(DIM, "\n  Enter para voltar..."))
    except (KeyboardInterrupt, EOFError):
        pass


def _opt(i, text, extra=""):
    return f"  {KEY}{i}){RESET} {text}" + (f"  {extra}" if extra else "")


def _tag(k):
    if os.path.isdir(os.path.join(TOOLS_DIR, k)):
        return paint(OK, "[instalado]")
    if FINDERS[k]():
        return paint(PURPLE, "[no sistema]")
    return paint(DIM, "[não instalado]")


def estado_linha():
    partes = []
    for k in ORDEM:
        on = bool(FINDERS[k]())
        partes.append((paint(OK, "●") if on else paint(DIM, "○")) + " " + paint(VAL if on else DIM, k))
    return "  " + paint(DIM, "ferramentas:  ") + "   ".join(partes)


def status_lines():
    out = [title("FERRAMENTAS")]
    for k in ORDEM:
        p = FINDERS[k]()
        if os.path.isdir(os.path.join(TOOLS_DIR, k)) and p:
            extra = f"{_dir_size_mb(os.path.join(TOOLS_DIR, k)):.0f} MB"
        else:
            extra = p or ""
        out.append(f"  {_tag(k):<30} {paint(VAL, NOMES[k])}  {paint(DIM, extra)}")
    out.append("")
    out.append(kv("Pasta", paint(DIM, TOOLS_DIR)))
    return out


def show_status():
    print("\n".join(status_lines()))


def remover_tudo():
    if not os.path.isdir(TOOLS_DIR):
        say("Nada instalado para remover.")
        return
    r = input(f"  Apagar TUDO em {TOOLS_DIR} ({_dir_size_mb(TOOLS_DIR):.0f} MB)? [s/N] ")
    if r.strip().lower() in ("s", "sim"):
        shutil.rmtree(TOOLS_DIR, onerror=lambda f, p, _e: (os.chmod(p, stat.S_IWRITE), f(p)))
        say("OK: tudo removido.")


def abrir_pasta(path):
    try:
        if IS_WIN:
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except OSError:
        pass


# ----------------------------------------------------------------------------
# 9) Análise completa
# ----------------------------------------------------------------------------
def analisar(arquivo, outdir=None, usar_rizin=False, usar_ghidra=False, usar_cutter=False,
             ghidra_dir=None, rizin_path=None, cutter_path=None, timeout=1800, log=None):
    """Extrai tudo e roda as ferramentas escolhidas. Devolve (pasta, relatório, extras)."""
    log = log or _log_extracao
    with open(arquivo, "rb") as f:
        data = f.read()
    outdir = outdir or (os.path.splitext(arquivo)[0] + "_extraido")

    info = parse_pe(data)
    log("Formato: " + ("PE (Windows)" if info else "não é PE; usando só busca por assinaturas"))
    rep = extract_all(data, info, outdir, log=log)

    extras = []
    if usar_rizin:
        rz = find_rizin(rizin_path)
        if rz:
            log("Rodando o rizin...")
            done = run_rizin(rz, arquivo, outdir, log=log)
            if done:
                extras.append(("rizin/", ", ".join(done)))
        else:
            log("  rizin não está instalado (menu > Instalar ferramentas)")
    if usar_ghidra:
        gh = find_ghidra(ghidra_dir)
        if gh:
            log("Rodando o Ghidra...")
            if run_ghidra(gh, arquivo, outdir, timeout=timeout, log=log):
                extras.append(("ghidra/", "decompilado.c (pseudo-código C de todas as funções)"))
        else:
            log("  Ghidra não está instalado (menu > Instalar ferramentas)")
    if extras:
        with open(os.path.join(outdir, "LEIAME.txt"), "a", encoding="utf-8") as f:
            f.write("\nFerramentas externas usadas:\n" + "\n".join(f"  {a:<12}: {b}" for a, b in extras) + "\n")
    if usar_cutter:
        ct = find_cutter(cutter_path)
        if ct and open_cutter(ct, arquivo):
            log("Cutter aberto.")
        else:
            log("  Cutter não está instalado (menu > Instalar ferramentas)")
    return outdir, rep, extras


def mostrar_resultado(outdir, rep, extras):
    print(title("RESULTADO"))
    width = max(40, term_size()[0] - 20)
    for nome, dica in rep["tecnologias"]:
        print(kv("Tecnologia", paint(OK, nome)))
        for ln in textwrap.wrap(dica, width):
            print("  " + " " * 15 + paint(DIM, ln))
    print()
    print(kv("Recursos", paint(VAL, f"{len(rep['recursos'])} item(ns)") + paint(DIM, "  recursos/")))
    print(kv("Embutidos", paint(VAL, f"{len(rep['embutidos'])} arquivo(s)") + paint(DIM, "  embutidos/")))
    py = rep["pyinstaller"]
    if py:
        print(kv("PyInstaller", paint(VAL, f"Python {py['python']} · {py['arquivos']} arquivos · "
                                           f"{py['modulos']} módulos") + paint(DIM, "  pyinstaller/")))
    for a, b in extras:
        print(kv("Extra", paint(VAL, a) + " " + paint(DIM, b)))
    print()
    print(kv("Pasta", paint(PINK, os.path.abspath(outdir))))
    print(kv("Resumo", paint(DIM, "LEIAME.txt")))


# ----------------------------------------------------------------------------
# 10) Telas e menu
# ----------------------------------------------------------------------------
def ask_path(first=None):
    while True:
        raw = first if first is not None else input(
            f"  {paint(KEY, 'Arquivo')} (arraste para cá, ou q para voltar): ")
        first = None
        raw = raw.strip().strip('"').strip("'")
        if raw.lower() == "q":
            return None
        if os.path.isfile(raw):
            return raw
        print(paint(ERR, "  Arquivo não encontrado."))


def tela_analisar(path=None):
    clear()
    banner()
    path = ask_path(path)
    if not path:
        return
    ordem = ["rizin", "ghidra", "cutter"]
    desc = {"rizin": "info, strings e assembly (rápido)",
            "ghidra": "decompila para C (lento, minutos)",
            "cutter": "abre a janela gráfica no final"}
    usar = {k: False for k in ordem}
    while True:
        clear()
        banner()
        print(kv("Arquivo", paint(VAL, f"{os.path.basename(path)}  ({human(os.path.getsize(path))})")))
        print(title("O QUE USAR ALÉM DA EXTRAÇÃO BÁSICA"))
        for i, k in enumerate(ordem, 1):
            box = paint(OK, "[x]") if usar[k] else paint(DIM, "[ ]")
            print(_opt(i, f"{box} {k:<8}{paint(DIM, f'{desc[k]:<38}')} {_tag(k)}"))
        print(f"\n  {paint(OK, 'Enter')} começa   {paint(KEY, '1 2 3')} marca/desmarca   {paint(DIM, '0 volta')}")
        try:
            s = input("\n  > ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if s == "":
            break
        if s == "0":
            return
        for ch in s.replace(",", " ").split():
            if ch.isdigit() and 1 <= int(ch) <= len(ordem):
                k = ordem[int(ch) - 1]
                usar[k] = not usar[k]

    clear()
    banner()
    for k in ordem:
        if usar[k] and not FINDERS[k]():
            say(f"{NOMES[k]} ainda não está instalado.")
            if not install_tool(k, True, say):
                usar[k] = False
    print()
    outdir, rep, extras = analisar(path, usar_rizin=usar["rizin"], usar_ghidra=usar["ghidra"],
                                   usar_cutter=usar["cutter"])
    mostrar_resultado(outdir, rep, extras)
    try:
        r = input(f"\n  {paint(KEY, 'a')} abrir a pasta   {paint(DIM, 'Enter voltar')} > ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return
    if r == "a":
        abrir_pasta(os.path.abspath(outdir))


def tela_instalar():
    itens = [("Ghidra (+ JDK 21 portátil)", ["ghidra"], "~800 MB"), ("rizin", ["rizin"], "~12 MB"),
             ("Cutter", ["cutter"], "~140 MB"), ("Todas", ["ghidra", "rizin", "cutter"], "~1 GB")]
    while True:
        clear()
        banner()
        print(title("INSTALAR FERRAMENTAS"))
        for i, (nome, keys, tam) in enumerate(itens, 1):
            st = _tag(keys[0]) if len(keys) == 1 else ""
            print(_opt(i, f"{nome:<28}{paint(DIM, f'{tam:<9}')}{st}"))
        print(f"  {DIM}0) Voltar{RESET}")
        print(paint(DIM, f"\n  Instala em: {TOOLS_DIR}"))
        try:
            op = input("\n  > ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if op == "0":
            return
        if not (op.isdigit() and 1 <= int(op) <= len(itens)):
            continue
        print()
        for k in itens[int(op) - 1][1]:
            if os.path.isdir(os.path.join(TOOLS_DIR, k)):
                say(f"{NOMES[k]} já está instalado.")
            else:
                install_tool(k, True, say)
        pausar()


def tela_desinstalar():
    itens = [("Ghidra", "ghidra"), ("rizin", "rizin"), ("Cutter", "cutter"),
             ("JDK portátil", "jdk"), ("Tudo (apaga a pasta inteira)", None)]
    while True:
        clear()
        banner()
        print(title("DESINSTALAR FERRAMENTAS"))
        for i, (nome, k) in enumerate(itens, 1):
            print(_opt(i, f"{nome:<32}{_tag(k) if k else ''}"))
        print(f"  {DIM}0) Voltar{RESET}")
        try:
            op = input("\n  > ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if op == "0":
            return
        if not (op.isdigit() and 1 <= int(op) <= len(itens)):
            continue
        print()
        k = itens[int(op) - 1][1]
        if k is None:
            remover_tudo()
        else:
            uninstall_tool(k, True, say)
        pausar()


def menu_principal(path=None):
    if path:
        tela_analisar(path)
    while True:
        clear()
        banner()
        print(estado_linha())
        print()
        print(_opt(1, "Analisar / extrair um programa"))
        print(_opt(2, "Instalar ferramentas  " + paint(DIM, "(Ghidra, rizin, Cutter)")))
        print(_opt(3, "Desinstalar ferramentas"))
        print(_opt(4, "Ver o que está instalado"))
        print(f"  {DIM}0) Sair{RESET}")
        try:
            op = input("\n  > ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        try:
            if op == "0":
                break
            elif op == "1":
                tela_analisar()
            elif op == "2":
                tela_instalar()
            elif op == "3":
                tela_desinstalar()
            elif op == "4":
                print("\n".join(status_lines()))
                pausar()
        except KeyboardInterrupt:
            print(paint(WARN, "\n  cancelado."))
            pausar()
        except Exception as exc:
            print(paint(ERR, f"\n  erro: {exc}"))
            pausar()
    print(RESET, end="")
    return 0


# ----------------------------------------------------------------------------
# 11) Linha de comando
# ----------------------------------------------------------------------------
def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Reverse Lab: extrai recursos, arquivos embutidos e conteúdo PyInstaller de um "
                    "executável (sem executá-lo). Sem argumentos (ou só com o arquivo), abre o menu.")
    ap.add_argument("arquivo", nargs="?", help="caminho do .exe / .dll / binário")
    ap.add_argument("-o", "--saida", help="pasta de saída (padrão: <arquivo>_extraido)")
    ap.add_argument("--ghidra", action="store_true", help="decompilar com o Ghidra (headless)")
    ap.add_argument("--rizin", action="store_true", help="gerar info/strings/assembly com o rizin")
    ap.add_argument("--cutter", action="store_true", help="abrir o arquivo no Cutter no final")
    ap.add_argument("--tudo", action="store_true", help="Ghidra + rizin + Cutter")
    ap.add_argument("--instalar", choices=ORDEM + ["tudo"], help="baixar e instalar uma ferramenta")
    ap.add_argument("--desinstalar", choices=ORDEM + ["tudo"], help="remover uma ferramenta")
    ap.add_argument("--status", action="store_true", help="mostrar o que está instalado")
    ap.add_argument("--sim", action="store_true", help="não pedir confirmação ao instalar/desinstalar")
    ap.add_argument("--menu", action="store_true", help="abrir o menu")
    ap.add_argument("--ghidra-dir", help="pasta de instalação do Ghidra")
    ap.add_argument("--rizin-path", help="caminho do rizin(.exe)")
    ap.add_argument("--cutter-path", help="caminho do Cutter(.exe)")
    ap.add_argument("--timeout", type=int, default=1800, help="limite do Ghidra em segundos (padrão 1800)")
    args = ap.parse_args(argv)

    tool_flags = args.ghidra or args.rizin or args.cutter or args.tudo
    cli = args.instalar or args.desinstalar or args.status or tool_flags
    if args.menu or not cli:
        return menu_principal(args.arquivo)

    ask = not args.sim
    if args.status:
        show_status()
    if args.instalar:
        for k in (["ghidra", "rizin", "cutter"] if args.instalar == "tudo" else [args.instalar]):
            install_tool(k, ask, say)
    if args.desinstalar:
        for k in (ORDEM if args.desinstalar == "tudo" else [args.desinstalar]):
            uninstall_tool(k, ask, say)

    if args.arquivo:
        if args.tudo:
            args.ghidra = args.rizin = args.cutter = True
        outdir, rep, extras = analisar(args.arquivo, args.saida, args.rizin, args.ghidra, args.cutter,
                                       args.ghidra_dir, args.rizin_path, args.cutter_path, args.timeout)
        mostrar_resultado(outdir, rep, extras)
    elif tool_flags:
        print(paint(ERR, "  Informe o arquivo a analisar, por exemplo: py app.py programa.exe --rizin"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())