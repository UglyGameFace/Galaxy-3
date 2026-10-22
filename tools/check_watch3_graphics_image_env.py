#!/usr/bin/env python3
"""Check effective R08 AsteroidOS graphics image dependency metadata.

Does NOT prove that target IPK binaries or an image rootfs have been built.
"""
import argparse
from pathlib import Path
import sys


def read_variable(environment: str, key: str) -> str | None:
    # bitbake -e records assignment history in comments; only the effective
    # final KEY="..." assignment is authoritative.
    for line in environment.splitlines():
        if line.startswith(key + '='):
            raw = line.partition('=')[2]
            return raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
    return None


def words(env: str, key: str) -> set[str]:
    return set((read_variable(env, key) or '').split())


def check_graphics_image_closure(
    image: str, launcher: str, qtbase: str, qtwayland: str, qtdeclarative: str
) -> list[str]:
    errors: list[str] = []
    environments = {
        'asteroid-image': image, 'asteroid-launcher': launcher,
        'qtbase': qtbase, 'qtwayland': qtwayland,
        'qtdeclarative': qtdeclarative,
    }
    for name, env in environments.items():
        machine = read_variable(env, 'MACHINE')
        if machine != 'noblesse-r08':
            errors.append(f'{name}: expected MACHINE=noblesse-r08, got {machine!r}')

    if read_variable(image, 'DISTRO') != 'asteroid':
        errors.append('asteroid-image DISTRO must be asteroid')
    if 'asteroid-launcher' not in words(image, 'IMAGE_INSTALL'):
        errors.append('asteroid-image IMAGE_INSTALL lacks asteroid-launcher')
    if 'wayland' not in words(image, 'DISTRO_FEATURES'):
        errors.append('asteroid-image DISTRO_FEATURES lacks wayland')

    runtime = words(launcher, 'RDEPENDS:asteroid-launcher')
    # Explicit run deps, not RRECOMMENDS: distros can disable recommendations.
    for pkg in ('qtbase-plugins', 'qtwayland-plugins',
                'qtdeclarative-qmlplugins', 'asteroid-launcher-configs'):
        if pkg not in runtime:
            errors.append(f'asteroid-launcher RDEPENDS lacks {pkg}')

    for name, env, package, expected_path in (
        ('qtbase', qtbase, 'qtbase-plugins', '/plugins/'),
        ('qtwayland', qtwayland, 'qtwayland-plugins', '/plugins/'),
        ('qtdeclarative', qtdeclarative, 'qtdeclarative-qmlplugins', '/qml'),
    ):
        if package not in words(env, 'PACKAGES'):
            errors.append(f'{name} PACKAGES does not create {package}')
        files = read_variable(env, f'FILES:{package}') or ''
        if expected_path not in files:
            errors.append(f'{package} FILES does not cover {expected_path}')

    if not {'gui', 'linuxfb'}.issubset(words(qtbase, 'PACKAGECONFIG')):
        errors.append('qtbase PACKAGECONFIG must include gui and linuxfb')
    if 'wayland' not in words(qtwayland, 'REQUIRED_DISTRO_FEATURES'):
        errors.append('qtwayland REQUIRED_DISTRO_FEATURES lacks wayland')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ('image', 'launcher', 'qtbase', 'qtwayland', 'qtdeclarative'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    paths = [getattr(args, key) for key in
             ('image', 'launcher', 'qtbase', 'qtwayland', 'qtdeclarative')]
    for path in paths:
        if not path.is_file():
            print(f'FAIL: missing effective BitBake environment: {path}', file=sys.stderr)
            return 1
    issues = check_graphics_image_closure(*(
        path.read_text(encoding='utf-8') for path in paths
    ))
    for issue in issues:
        print('FAIL: ' + issue, file=sys.stderr)
    if issues:
        return 1
    print('PASS[metadata]: R08 AsteroidOS image requests asteroid-launcher and Wayland')
    print('PASS[metadata]: launcher hard-depends on LinuxFB, Wayland and QML plugin packages')
    print('PASS[metadata]: effective Qt recipes split QPA and QML files into those packages')
    print('NOT TESTED: target IPK contents, ARM64 image rootfs, watch framebuffer or boot')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
