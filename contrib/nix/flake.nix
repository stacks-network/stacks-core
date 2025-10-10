{
  description = "stacks-core";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";

    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane = { url = "github:ipetkov/crane"; };

  };

  outputs = { nixpkgs, flake-utils, rust-overlay, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        inherit (pkgs) lib;

        toolchain = pkgs.rust-bin.fromRustupToolchainFile ../../rust-toolchain;
        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        name = "stacks-core";

        versions = (builtins.fromTOML (builtins.readFile ../../versions.toml));
        version = versions.stacks_node_version;

        # Common arguments can be set here to avoid repeating them later
        commonArgs = {
          strictDeps = true;

          buildInputs = [
            # Add additional build inputs here
          ] ++ lib.optionals pkgs.stdenv.isDarwin [
            # Darwin specific inputs
          ];
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          inherit version;
          pname = name;
          src = fileSetForCrate ../..;
        });

        individualCrateArgs = commonArgs // {
          inherit cargoArtifacts;

          # NB: we disable tests since we'll run them all via cargo-nextest
          doCheck = false;
        };

        # TODO: Return minimum fileSets per each crate
        fileSetForCrate = crate:
          lib.fileset.toSource {
            root = ../..;
            fileset = lib.fileset.unions [
              ../../Cargo.toml
              ../../Cargo.lock
              #
              ../../versions.toml
              #
              ../../stx-genesis/name_zonefiles.txt
              ../../stx-genesis/name_zonefiles.txt.sha256
              ../../stx-genesis/name_zonefiles-test.txt
              ../../stx-genesis/name_zonefiles-test.txt.sha256
              ../../stx-genesis/chainstate.txt
              ../../stx-genesis/chainstate.txt.sha256
              ../../stx-genesis/chainstate-test.txt
              ../../stx-genesis/chainstate-test.txt.sha256
              #
              (craneLib.fileset.commonCargoSources crate)
              #
              (lib.fileset.fileFilter (file: file.hasExt "clar") ../..)
              #
              (craneLib.fileset.commonCargoSources ../../clarity)
              (craneLib.fileset.commonCargoSources ../../clarity-types)
              ../../clarity-types/README.md
              (craneLib.fileset.commonCargoSources ../../libsigner)
              (craneLib.fileset.commonCargoSources ../../libstackerdb)
              (craneLib.fileset.commonCargoSources ../../pox-locking)
              (craneLib.fileset.commonCargoSources ../../stacks-common)
              (craneLib.fileset.commonCargoSources ../../stackslib)
              (craneLib.fileset.commonCargoSources ../../stx-genesis)
              (craneLib.fileset.commonCargoSources ../../stacks-node)
              (craneLib.fileset.commonCargoSources
                ../tools/config-docs-generator)
              (craneLib.fileset.commonCargoSources ../../contrib/stacks-inspect)
              (craneLib.fileset.commonCargoSources ../../contrib/stacks-cli)
              (craneLib.fileset.commonCargoSources ../../stacks-signer)
            ];
          };

        stacks-signer = craneLib.buildPackage (individualCrateArgs // rec {
          version = versions.stacks_signer_version;
          pname = "stacks-signer";
          cargoFeatures = "--features monitoring_prom";
          cargoExtraArgs = "${cargoFeatures} -p ${pname}";
          src = fileSetForCrate ../../stacks-signer;
        });

        # Build the actual crate itself, reusing the dependency
        # artifacts from above.
        stacks-core = craneLib.buildPackage (commonArgs // rec {
          inherit version cargoArtifacts;
          doCheck = false;
          pname = name;
          cargoFeatures = "--features monitoring_prom,slog_json";
          cargoExtraArgs = "${cargoFeatures}";
          src = fileSetForCrate ../..;
        });

        stacks-inspect = craneLib.buildPackage (individualCrateArgs // rec {
          inherit version;
          pname = "stacks-inspect";
          cargoExtraArgs = "-p ${pname}";
          src = fileSetForCrate ../../contrib/stacks-inspect;
        });

        stacks-cli = craneLib.buildPackage (individualCrateArgs // rec {
          inherit version;
          pname = "stacks-cli";
          cargoExtraArgs = "-p ${pname}";
          src = fileSetForCrate ../../contrib/stacks-cli;
        });

        stacks-node-app = {
          type = "app";
          program = "${stacks-core}/bin/stacks-node";
          meta = with lib; {
            license = licenses.gpl3;
            platforms = platforms.all;
            description = "The Stacks blockchain implementation.";
            homepage = "https://stacks.co";
          };
        };

        stacks-signer-app = {
          type = "app";
          program = "${stacks-signer}/bin/stacks-signer";
          meta = with lib; {
            license = licenses.gpl3;
            platforms = platforms.all;
            description = "Signer for the Stacks blockchain implementation.";
            homepage = "https://stacks.co";
          };
        };
      in with pkgs; {
        packages = {
          inherit stacks-signer stacks-core stacks-cli stacks-inspect;
          default = stacks-core;
        };

        apps = {
          stacks-node = stacks-node-app;
          default = stacks-node-app;
          stacks-signer = stacks-signer-app;
        };

        checks = {
          workspaceCheck = craneLib.buildPackage (commonArgs // rec {
            inherit version cargoArtifacts;
            cargoBuildCommand = "cargo check --workspace";
            doCheck = false;
            pname = name;
            cargoFeatures = "--features monitoring_prom,slog_json";
            cargoExtraArgs = "${cargoFeatures}";
            src = fileSetForCrate ../..;
          });
        };

        devShells.default = craneLib.devShell {
          RUSTFMT = "${toolchain}/bin/rustfmt";
          GREETING = "Welcome, stacks-core developer!";
          shellHook = ''
            echo $GREETING

            echo "Setting a few options that will help you when running tests:"
            set -x
            ulimit -n 10240
            set +x
          '';

          packages = [ rust-analyzer bitcoind cargo-nextest ]
            ++ lib.optionals pkgs.stdenv.isDarwin [ ];
        };
      });
}
