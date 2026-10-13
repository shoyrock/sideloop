import json
import os
import plistlib
import re
import struct
import sys
import zipfile
from pathlib import Path

LC_ENCRYPTION_INFO = (0x21, 0x2C)
CPU_ARM64 = 0x0100000C
FAT_MAGIC = (0xCAFEBABE, 0xCAFEBABF)
MACHO_MAGIC = (0xFEEDFACF, 0xFEEDFACE)
CACHE_VERSION = 4
# Extensions, widgets, watch apps and app clips each need their own App ID and take one of the
# device's 3 free-app slots. Like AltStore and SideStore, Sideloop removes them unless kept.
EXTRAS = re.compile(r"Payload/[^/]+\.app/(?:PlugIns|Extensions|Watch|AppClips)/")


# Bundle identifiers name the app's storage folder; Apple allows letters, digits, "-" and ".".
BUNDLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")
VERSION = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}")
MAX_ENTRIES = 300_000
MAX_UNPACKED = 16 * 1024 ** 3


def _unsafe(z):
    """Why an archive can't be accepted: AltServer extracts it, so members must stay inside it."""
    entries = z.infolist()
    if len(entries) > MAX_ENTRIES:
        return "the IPA has too many files"
    if sum(i.file_size for i in entries) > MAX_UNPACKED:
        return "the IPA unpacks to more than 16 GB"
    for i in entries:
        name = i.filename
        parts = name.replace("\\", "/").split("/")
        if not name or name.startswith(("/", "\\")) or "\x00" in name or ":" in parts[0] or ".." in parts:
            return "the IPA contains files outside the app (unsafe archive)"
    return ""


def version_key(v):
    parts = [int(x) for x in re.findall(r"\d+", str(v))[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def requires_newer(min_ios, ios):
    """True when the device's iOS is known and older than the app's minimum."""
    return bool(min_ios and ios and re.match(r"\d", ios)) and version_key(min_ios) > version_key(ios)


def _cryptid(z, member):
    with z.open(member) as f:
        head = f.read(4096)
        base = 0
        magic = struct.unpack(">I", head[:4])[0]
        if magic in FAT_MAGIC:
            wide = magic == 0xCAFEBABF
            step = 32 if wide else 20
            for i in range(struct.unpack(">I", head[4:8])[0]):
                e = head[8 + i * step: 8 + (i + 1) * step]
                if struct.unpack(">I", e[:4])[0] == CPU_ARM64:
                    base = struct.unpack(">Q", e[8:16])[0] if wide else struct.unpack(">I", e[8:12])[0]
                    break
            f.seek(base)
            head = f.read(4096)
        magic = struct.unpack("<I", head[:4])[0]
        if magic not in MACHO_MAGIC:
            return None
        hsize = 32 if magic == 0xFEEDFACF else 28
        ncmds, sizeofcmds = struct.unpack("<II", head[16:24])
        if hsize + sizeofcmds > len(head):
            f.seek(base)
            head = f.read(hsize + sizeofcmds)
        off = hsize
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", head[off:off + 8])
            if cmd in LC_ENCRYPTION_INFO:
                return struct.unpack("<I", head[off + 16:off + 20])[0]
            off += size
        return 0


def inspect(path):
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return {"error": "not an IPA (an IPA is a zip file)"}
    with z:
        names = z.namelist()
        if problem := _unsafe(z):
            return {"error": problem}
        info = next((n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)), None)
        if not info:
            return {"error": "not an iOS app archive (no Payload/*.app/Info.plist)"}
        app = info.rsplit("/", 1)[0]
        try:
            p = plistlib.loads(z.read(info))
        except Exception:
            return {"error": "the app's Info.plist can't be read"}
        if not BUNDLE_ID.fullmatch(str(p.get("CFBundleIdentifier", ""))) or ".." in p["CFBundleIdentifier"]:
            return {"error": "the app's bundle identifier isn't valid"}
        exe = p.get("CFBundleExecutable", "")
        try:
            enc = _cryptid(z, f"{app}/{exe}")
        except Exception:
            enc = None
        tweaks = sorted({n.rsplit("/", 1)[1] for n in names if n.startswith(app + "/") and n.endswith(".dylib")})
        appex = sorted({m.group(1) for n in names
                        for m in [re.match(re.escape(app) + r"/PlugIns/([^/]+)\.appex/", n)] if m})
        # iOS refuses the whole install if the app or any extension needs a newer version.
        mins = [p.get("MinimumOSVersion", "")]
        for name in appex:
            try:
                mins.append(plistlib.loads(z.read(f"{app}/PlugIns/{name}.appex/Info.plist")).get("MinimumOSVersion", ""))
            except (KeyError, ValueError, plistlib.InvalidFileException):
                pass
        # Untrusted text from the IPA; keep only well-formed versions.
        mins = [m for m in mins if isinstance(m, str) and VERSION.fullmatch(m)]
        min_ios = max(mins, key=version_key, default="")
        size = sum(i.file_size for i in z.infolist())
    return {
        "name": p.get("CFBundleDisplayName") or p.get("CFBundleName") or exe,
        "bundle_id": p.get("CFBundleIdentifier", ""),
        "version": p.get("CFBundleShortVersionString", ""),
        "build": p.get("CFBundleVersion", ""),
        "min_ios": min_ios,
        "app_min_ios": p.get("MinimumOSVersion", "") if VERSION.fullmatch(str(p.get("MinimumOSVersion", ""))) else "",
        "size_mb": f"{size / 1e6:.0f}",
        "encrypted": {1: "yes", 0: "no"}.get(enc, "unknown"),
        "tweaks": ", ".join(tweaks),
        "tweak_count": len(tweaks),
        "extensions": ", ".join(appex),
        "extension_count": len(appex),
    }


def cached(folder):
    ipa, cache = folder / "app.ipa", folder / "info.json"
    if not ipa.exists():
        return None
    mtime = ipa.stat().st_mtime
    try:
        info = json.loads(cache.read_text())
        if info.get("_mtime") == mtime and info.get("_v") == CACHE_VERSION:
            return info
    except (FileNotFoundError, ValueError):
        pass
    info = inspect(ipa) | {"_mtime": mtime, "_v": CACHE_VERSION}
    cache.write_text(json.dumps(info))
    return info


def required_ios(info, keep_extensions=False):
    """The minimum iOS for what is actually installed: without extensions, only the app's own."""
    info = info or {}
    return info.get("min_ios", "") if keep_extensions else info.get("app_min_ios", info.get("min_ios", ""))


def signing_copy(folder, keep_extensions=False):
    """The IPA to sign: the upload itself, or a cached copy without its extensions."""
    folder = Path(folder)
    ipa, stripped = folder / "app.ipa", folder / "app-noext.ipa"
    if keep_extensions or not zipfile.is_zipfile(ipa):
        return ipa
    with zipfile.ZipFile(ipa) as z:
        if not any(EXTRAS.match(n) for n in z.namelist()):
            return ipa
        if stripped.exists() and stripped.stat().st_mtime >= ipa.stat().st_mtime:
            return stripped
        tmp = stripped.with_suffix(".tmp")
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as out:
            for item in z.infolist():
                if not EXTRAS.match(item.filename):
                    with z.open(item) as src, out.open(item, "w", force_zip64=True) as dst:
                        while chunk := src.read(1 << 20):
                            dst.write(chunk)
    tmp.replace(stripped)
    return stripped


if __name__ == "__main__":
    # refresh.sh: with a device iOS, exit 3 and print the app's minimum when it's too old;
    # without one, print the app's minimum.
    # refresh.sh exports the app's meta.env, including KEEP_EXTENSIONS.
    keep = os.environ.get("KEEP_EXTENSIONS") == "1"
    if sys.argv[1] == "--signing-copy":
        print(signing_copy(sys.argv[2], keep))
        sys.exit()
    folder, *ios = sys.argv[1:]
    min_ios = required_ios(cached(Path(folder)), keep)
    if not ios:
        print(min_ios)
    elif requires_newer(min_ios, ios[0]):
        print(min_ios)
        sys.exit(3)
