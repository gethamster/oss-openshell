# Managed System releases

`release.json` runs the System federation release through the managed Dagger
controller. Set `OPENSHELL_VERSION` to the accepted `0.1.6-system.N` version in
the controller configuration; that value is part of the build identity.

Linux workers use the pinned Nix image and this repository's `flake.lock`, Rust
toolchain, GNU sysroots and musl CLI targets. The native macOS ARM64 worker needs
Nix installed and uses `.dagger/native.json` with the same release shell. The
recipe preserves the issuer-federation and credential-isolation checks, builds
each auditable binary once, verifies its embedded Cargo metadata with Syft, and
retains its SBOM and deterministic archive. Both license files are included.

The controller owns source admission, artifact receipts and R2 publication.
Source and publication credentials are not inputs to these build commands.
The existing GitHub release workflow remains enabled until the managed outputs
have completed platform and runtime qualification.
