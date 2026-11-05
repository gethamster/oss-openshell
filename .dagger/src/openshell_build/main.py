# SPDX-FileCopyrightText: Copyright (c) 2026 Hamster
# SPDX-License-Identifier: Apache-2.0

"""Use the repository's locked Nix release toolchain on Foundry."""
import json
from typing import Annotated

import dagger
from dagger import DefaultPath, dag, function, object_type

NIX = 'nixos/nix@sha256:29fc5fe207f159ceb0143c25c19c774062fee02ce5eda118f3067547b3054894'


@object_type
class OpenShellBuild:
    def container(self, source, platform, variables):
        if platform not in {'linux/amd64', 'linux/arm64'}:
            raise ValueError('macOS uses the enrolled native Nix worker')
        values = json.loads(variables)
        if set(values) != {'OPENSHELL_VERSION'}:
            raise ValueError('Select the exact OpenShell release version')
        base = dag.container(platform=dagger.Platform(platform)).from_(NIX)
        return (base.with_mounted_cache('/nix', dag.cache_volume('openshell-nix-' + platform),
                                        source=base.directory('/nix'))
                .with_mounted_cache('/cargo', dag.cache_volume('openshell-cargo'))
                .with_mounted_cache('/target', dag.cache_volume('openshell-target-' + platform))
                .with_env_variable('CARGO_HOME', '/cargo').with_env_variable('CARGO_TARGET_DIR', '/target')
                .with_env_variable('CARGO_BUILD_JOBS', '2').with_env_variable('CARGO_INCREMENTAL', '0')
                .with_env_variable('OPENSHELL_VERSION', values['OPENSHELL_VERSION'])
                .with_env_variable('NIX_CONFIG', 'experimental-features = nix-command flakes\nsandbox = false\n')
                .with_directory('/source', source, exclude=['.git', 'target', 'dist-native'])
                .with_workdir('/source'))

    @function
    async def test(self, platform: str, source: Annotated[dagger.Directory, DefaultPath('/')], variables: str = '{}') -> str:
        return await self.container(source, platform, variables).with_exec([
            'nix', 'develop', '.#release', '--no-write-lock-file', '--accept-flake-config',
            '-c', 'uv', 'run', '--no-project', '--python', 'python3', 'python', '.dagger/release.py', 'test']).stdout()

    @function
    def build(self, platform: str, source: Annotated[dagger.Directory, DefaultPath('/')], variables: str = '{}') -> dagger.Directory:
        return self.container(source, platform, variables).with_exec([
            'nix', 'develop', '.#release', '--no-write-lock-file', '--accept-flake-config',
            '-c', 'uv', 'run', '--no-project', '--python', 'python3', 'python', '.dagger/release.py', 'build']).directory('/source/dist-native')
