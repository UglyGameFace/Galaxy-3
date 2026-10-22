#!/usr/bin/env python3
"""Inspect real extracted Watch3 R08 ARM64 rootfs files, without executing them.

This is a post-build artifact gate. Do not infer success from BitBake metadata.
Do not run on the watch or invoke a bootloader/flashing utility.
"""
import argparse
from pathlib import Path
import struct
import sys

ARM64 = 183
REQUIRED_MANIFEST = frozenset({
    'asteroid-launcher', 'asteroid-launcher-configs',
    'qtbase-plugins', 'qtwayland-plugins', 'qtdeclarative-qmlplugins',
})


def elf_aarch64(path: Path) -> tuple[bool, str]:
    try:
        with path.open('rb') as stream:
            header = stream.read(64)
    except OSError as exc:
        return False, f'unreadable: {exc}'
    if len(header) < 64 or header[:4] != b'\x7fELF':
        return False, 'not a complete ELF64 header'
    if header[4] != 2:
        return False, 'not ELF64'
    # This Watch3's Cortex-A53 target is aarch64 little-endian, not BE8.
    if header[5] != 1 or header[6] != 1:
        return False, 'not little-endian ELF version 1'
    elf_type, machine = struct.unpack_from('<HH', header, 16)
    if machine != ARM64:
        return False, f'wrong ELF machine e_machine={machine}; expected AArch64=183'
    if elf_type not in (2, 3):
        return False, f'ELF type {elf_type} is not executable or shared-object'
    header_size = struct.unpack_from('<H', header, 52)[0]
    if header_size != 64:
        return False, f'ELF64 header size is {header_size}, expected 64'
    return True, 'ELF64 little-endian AArch64 executable/shared-object'

def matching_files(rootfs: Path, pattern: str) -> list[Path]:
    """Find real in-rootfs files while preventing misleading outbound symlinks."""
    root = rootfs.resolve()
    found = []
    for base in ('usr/lib', 'usr/lib64', 'lib', 'lib64'):
        folder = rootfs / base
        if not folder.is_dir():
            continue
        for path in folder.glob(pattern):
            if not path.is_file() or not path.resolve().is_relative_to(root):
                continue
            found.append(path)
    return sorted(set(found))


def validate(rootfs: Path, package_manifest: Path | None = None) -> list[str]:
    errors: list[str] = []
    if not rootfs.is_dir():
        return [f'missing extracted rootfs directory: {rootfs}']

    config = rootfs / 'var/lib/environment/compositor/10-platform.conf'
    if not config.is_file() or not config.resolve().is_relative_to(rootfs.resolve()):
        errors.append('missing R08 compositor config: var/lib/environment/compositor/10-platform.conf')
    else:
        settings = {line.strip() for line in config.read_text(errors='replace').splitlines()}
        for needed in ('QT_QPA_PLATFORM=linuxfb', 'QT_QUICK_BACKEND=software', 'QT_QPA_FB_DRM=0'):
            if needed not in settings:
                errors.append(f'R08 compositor config missing {needed}')

    launcher = rootfs / 'usr/bin/asteroid-launcher'
    if not launcher.is_file() or not launcher.resolve().is_relative_to(rootfs.resolve()):
        errors.append('missing /usr/bin/asteroid-launcher')
    else:
        okay, reason = elf_aarch64(launcher)
        if not okay:
            errors.append(f'asteroid-launcher: {reason}')

    service = rootfs / 'usr/lib/systemd/user/asteroid-launcher.service'
    if not service.is_file() or not service.resolve().is_relative_to(rootfs.resolve()):
        errors.append('missing user service: usr/lib/systemd/user/asteroid-launcher.service')
    else:
        content = service.read_text(errors='replace')
        if '/var/lib/environment/compositor/' not in content:
            errors.append('launcher service does not load R08 compositor environment')

    binary_specs = {
        'LinuxFB QPA': '**/plugins/platforms/libqlinuxfb.so',
        'Wayland client QPA': '**/plugins/platforms/libqwayland*.so',
        'QtWayland compositor library': '**/libQt6WaylandCompositor.so.*',
    }
    for label, pattern in binary_specs.items():
        paths = matching_files(rootfs, pattern)
        if not paths:
            errors.append(f'missing {label} binary: {pattern}')
            continue
        valid = []
        invalid = []
        for path in paths:
            okay, reason = elf_aarch64(path)
            (valid if okay else invalid).append(str(path.relative_to(rootfs)) if okay
                else f'{path.relative_to(rootfs)} ({reason})')
        if not valid:
            errors.append(f'{label} has no ELF64 AArch64 binary; found: {invalid}')

    # QtQuick is directly imported by the pinned AsteroidOS launcher. The
    # actual import path is resolved from rootfs, not guessed from host Ubuntu.
    quick = matching_files(rootfs, '**/qml/QtQuick/qmldir')
    if not quick:
        errors.append('missing QtQuick QML qmldir in target rootfs')

    if package_manifest is not None:
        if not package_manifest.is_file():
            errors.append(f'missing installed-package manifest: {package_manifest}')
        else:
            # Yocto installed-package-names.txt: one package name per line.
            # Yocto IMAGE_MANIFEST lines are: package arch version; a
            # one-name-per-line manifest is also accepted for fixture tests.
            packages = {
                line.split()[0]
                for line in package_manifest.read_text(errors='replace').splitlines()
                if line.strip() and not line.lstrip().startswith('#')
            }
            for name in sorted(REQUIRED_MANIFEST - packages):
                errors.append(f'installed-package manifest lacks {name}')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path, help='already-extracted ARM64 image rootfs directory')
    parser.add_argument('--installed-packages', type=Path,
                        help='optional Yocto installed-package-names.txt for stronger package closure')
    args = parser.parse_args()
    problems = validate(args.rootfs, args.installed_packages)
    for problem in problems:
        print('FAIL[rootfs]: ' + problem, file=sys.stderr)
    if problems:
        return 1
    print('PASS[rootfs]: R08 launcher, LinuxFB, Wayland QPA, QtWayland compositor and QtQuick QML files')
    print('PASS[rootfs]: checked ELF64 AArch64 binary headers and R08 compositor environment')
    if args.installed_packages:
        print('PASS[rootfs]: installed-package manifest includes required graphics runtime packages')
    print('NOT TESTED: executable startup, kernel framebuffer /dev/fb0, watch boot or recovery')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
