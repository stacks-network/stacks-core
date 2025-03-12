# `nix` flake

Build `stacks-node` and `stacks-signer` by pointing to the `flake.nix` file in
this directory. For instance, from the root directory: `nix build
'./contrib/nix'`.

## Installing `nix`

Follow the [official documentation](https://nix.dev/install-nix) or use the
[Determinate Nix Installer](https://github.com/DeterminateSystems/nix-installer).

## Using `direnv`

If using `direnv`, from the root directory of this repository:

```bash
echo "use flake ./contrib/nix/" > .envrc
direnv allow
```

This will provide a `sh` environment with required dependencies (e.g., `bitcoind`) available.
