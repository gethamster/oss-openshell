#!/usr/bin/env python3
"""Run the existing auditable federation release checks and package retained binaries."""
import gzip
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile


def run(arguments):
    subprocess.run(arguments, check=True)


def target_pair():
    machine = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x86_64': 'x86_64'}.get(platform.machine())
    if platform.system() == 'Darwin' and machine == 'aarch64':
        return 'aarch64-apple-darwin', 'aarch64-apple-darwin'
    if platform.system() == 'Linux' and machine:
        return machine + '-unknown-linux-musl', machine + '-unknown-linux-gnu'
    raise ValueError('Unsupported release worker')


def prepare():
    version = os.environ.get('OPENSHELL_VERSION', '')
    if not re.fullmatch(r'0\.1\.6-system\.[1-9][0-9]*', version):
        raise ValueError('Select an exact System federation release version')
    manifest = Path('Cargo.toml')
    text = manifest.read_text()
    pattern = r'(?m)^version = "(?:0\.0\.0|' + re.escape(version) + r')"$'
    text, count = re.subn(pattern, 'version = "' + version + '"', text)
    if count != 1:
        raise ValueError('Workspace version does not match the release input')
    manifest.write_text(text)
    os.environ.update(GIT_DIR='/nonexistent', OPENSHELL_IMAGE_TAG='0.1.6')
    return version


def test(gateway):
    run(['cargo', 'test', '--locked', '--release', '--target', gateway, '-p', 'openshell-server', '--lib',
         'auth::oidc::federation::tests'])
    common = ['cargo', 'nextest', 'run', '--locked', '--release', '--profile', 'ci', '--target', gateway,
              '--lib', '--color', 'never', '--no-tests=fail']
    run([*common, '-p', 'openshell-driver-db-credstore'])
    run([*common, '-p', 'openshell-server', '-E',
         'test(/^(credentials|grpc::provider_credentials|ssh_identity|supervisor_pool)::tests::/)'])


def build(version, cli, gateway):
    output = Path('dist-native')
    output.mkdir(exist_ok=True)
    for package, binary, target in [('openshell-cli', 'openshell', cli),
                                    ('openshell-gateway', 'openshell-gateway', gateway)]:
        run(['cargo', 'auditable', 'build', '--locked', '--release', '--target', target,
             '--package', package, '--bin', binary])
        path = Path(os.environ.get('CARGO_TARGET_DIR', 'target')) / target / 'release' / binary
        reported = subprocess.check_output([str(path.resolve()), '--version'], text=True).strip()
        if not reported.startswith(binary + ' ' + version):
            raise ValueError('Built binary version differs from its selected input')
        sbom = subprocess.check_output(['syft', 'file:' + str(path), '-o', 'cyclonedx-json'],
                                       env={**os.environ, 'SYFT_CHECK_FOR_APP_UPDATE': 'false'})
        if not any(row.get('purl', '').startswith('pkg:cargo/') for row in json.loads(sbom).get('components', [])):
            raise ValueError('Auditable Rust dependency metadata is missing')
        (output / (binary + '.cdx.json')).write_bytes(sbom)
        with (output / (binary + '-' + target + '.tar.gz')).open('wb') as raw:
            with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as archive:
                    for source, name in [(path, 'bin/' + binary), (Path('LICENSE'), 'LICENSE'),
                                         (Path('LICENSE-UPSTREAM'), 'LICENSE-UPSTREAM')]:
                        info = tarfile.TarInfo(name)
                        info.size = source.stat().st_size
                        info.mode = 0o755 if name.startswith('bin/') else 0o644
                        with source.open('rb') as stream:
                            archive.addfile(info, stream)


if __name__ == '__main__':
    version = prepare()
    cli, gateway = target_pair()
    if sys.argv[1:] == ['test']:
        test(gateway)
    elif sys.argv[1:] == ['build']:
        build(version, cli, gateway)
    else:
        raise ValueError('Expected test or build phase')
