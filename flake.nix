{
  description = "Tacet - E2E encrypted AI inference gateway";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      in {
        devShells.default = pkgs.mkShell {
          name = "tacet-builder";

          buildInputs = [
            # mkosi with QEMU support
            pkgs.mkosi-full
            pkgs.qemu
            pkgs.qemu-utils

            # Filesystem tools required by mkosi
            pkgs.dosfstools
            pkgs.e2fsprogs
            pkgs.cryptsetup
            pkgs.squashfsTools
            pkgs.mtools

            # Ubuntu/Debian package management (for mkosi)
            pkgs.apt
            pkgs.dpkg
            pkgs.debootstrap
            pkgs.gnupg

            # Python tooling
            pkgs.python312
            pkgs.python312Packages.pip
            pkgs.python312Packages.virtualenv

            # Utilities
            pkgs.git
            pkgs.gnumake
            pkgs.coreutils
            pkgs.util-linux
            pkgs.binutils
            pkgs.gzip
            pkgs.xz
            pkgs.zstd
          ];

          shellHook = ''
            echo "Tacet Image Builder"
            echo "==================="
            echo ""
            echo "Commands:"
            echo "  cd tee/image && make build   - Build VM image"
            echo "  cd tee/image && make clean   - Clean build artifacts"
            echo ""
            echo "mkosi version: $(mkosi --version)"
          '';
        };

        packages.default = pkgs.mkosi-full;
      }
    );
}
