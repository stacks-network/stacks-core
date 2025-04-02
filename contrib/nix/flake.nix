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

    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs =
    { self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        inherit (pkgs) lib;

        toolchain = pkgs.rust-bin.fromRustupToolchainFile ../../rust-toolchain;
        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        name = "stacks-core";

        versions = (builtins.fromTOML (builtins.readFile ../../versions.toml));
        version = versions.stacks_node_version;

        # Common arguments can be set here to avoid repeating them later
        baseArgs = {
          strictDeps = true;

          buildInputs =
            [
              # Add additional build inputs here
            ]
            ++ lib.optionals pkgs.stdenv.isDarwin [
              # Darwin specific inputs
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];

            src = fileSetForCrate ../..;
            inherit version;
        };

         isClarityWASM = p: lib.hasPrefix "git+https://github.com/stacks-network/clarity-wasm.git" p.source;

         cargoVendorDir = craneLib.vendorCargoDeps (
           baseArgs
           // {
             # Use this function to override crates coming from git dependencies
             overrideVendorGitCheckout =
               ps: drv:
               if lib.any (p: isClarityWASM p) ps then
                 drv.overrideAttrs (_old: {
                   patches = [
                     (builtins.fetchurl {
                       url = "https://github.com/stacks-network/clarity-wasm/pull/627.patch";
                       sha256 = "sha256:161mx1m21770lrsc2lfqlwzyydhy8f9bc7pmqb26rcki7s2ar31r";
                     })
                   ];
                 })
               else
                 # Nothing to change, leave the derivations as is
                 drv;

             # Use this function to override crates coming from any registry checkout
             overrideVendorCargoPackage = p: drv: drv;
           }
         );

        commonArgs = baseArgs // {
          inherit cargoVendorDir;
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            pname = name;
            dummySrc = commonArgs.src;
          }
        );

        individualCrateArgs = commonArgs // {
          inherit cargoArtifacts;

          # NB: we disable tests since we'll run them all via cargo-nextest
          doCheck = false;
        };

        # TODO: Return minimum fileSets per each crate
        fileSetForCrate =
          crate:
          lib.fileset.toSource {
            root = ../..;
            fileset = lib.fileset.unions [
              (craneLib.fileset.commonCargoSources ../..)
              (craneLib.fileset.configToml ../..)
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
              (craneLib.fileset.commonCargoSources ../../contrib/tools/relay-server)
              (craneLib.fileset.commonCargoSources ../../libsigner)
              (craneLib.fileset.commonCargoSources ../../libstackerdb)
              (craneLib.fileset.commonCargoSources ../../pox-locking)
              (craneLib.fileset.commonCargoSources ../../stacks-common)
              (craneLib.fileset.commonCargoSources ../../stackslib)
              (craneLib.fileset.commonCargoSources ../../stx-genesis)
              (craneLib.fileset.commonCargoSources ../../testnet/stacks-node)
            ];
          };

        stacks-signer = craneLib.buildPackage (
          individualCrateArgs
          // rec {
            version = versions.stacks_signer_version;
            pname = "stacks-signer";
            cargoFeatures = "--features monitoring_prom";
            cargoExtraArgs = "${cargoFeatures} -p ${pname}";
            src = fileSetForCrate ../../stacks-signer;
          }
        );

        stacks-common = craneLib.buildPackage (
          individualCrateArgs
          // rec {
            version = (builtins.fromTOML (builtins.readFile ../../stacks-common/Cargo.toml)).package.version;
            pname = "stacks-common";
            cargoFeatures = "--features slog_json";
            cargoExtraArgs = "${cargoFeatures} -p ${pname}";
            src = fileSetForCrate ../../stacks-common;
          }
        );

        # Build the actual crate itself, reusing the dependency
        # artifacts from above.
        stacks-core = craneLib.buildPackage (
          commonArgs
          // rec {
            inherit version cargoArtifacts;
            doCheck = false;
            pname = name;
            cargoFeatures = "--features monitoring_prom,slog_json";
            cargoExtraArgs = "${cargoFeatures}";
            src = fileSetForCrate ../..;
          }
        );
      in
      with pkgs;
      {
        packages = {
          inherit stacks-signer stacks-common cargoArtifacts stacks-core;
          default = stacks-core;
        };

        apps = rec {
          stacks-node = {
            type = "app";
            program = "${stacks-core}/bin/stacks-node";
          };
          stacks-signer = {
            type = "app";
            program = "${stacks-signer}/bin/stacks-signer";
          };
          default = stacks-node;
        };

        checks = self.packages."${system}";

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

          packages =
            [
              rust-analyzer
              bitcoind
            ]
            ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
              pkgs.darwin.apple_sdk.frameworks.CoreServices
            ];
        };
      }
    );
}
