# local config
__ROOT="$(realpath "$(pwd)"/..)"
__ETC="$__ROOT/etc"
__MNT="$__ROOT/mnt"

BITCOIN_CONF="$__ETC/bitcoin.conf"
BITCOIN_CONTROLLER_CONF="$__ETC/bitcoin-neon-controller.toml"
STACKS_MASTER_CONF="$__ETC/stacks-master.toml"
STACKS_MINER_CONF="$__ETC/stacks-miner.toml"
STACKS_FOLLOWER_CONF="$__ETC/stacks-follower.toml"

BITCOIN_LOGFILE="$__MNT/bitcoin.log"
BITCOIN_NEON_CONTROLLER_LOGFILE="$__MNT/bitcoin-neon-controller.log"

STACKS_MASTER_LOGFILE="$__MNT/stacks-node-master.log"
STACKS_MINER_LOGFILE="$__MNT/stacks-node-miner.log"
STACKS_FOLLOWER_LOGFILE="$__MNT/stacks-node-follower.log"
FAUCET_LOGFILE="$__MNT/faucet.log"

STACKS_MASTER_PUBLIC_IP="127.0.0.1"

FAUCET_PORT=8080

__NOW="$(date +%s)"
STACKS_CHAINSTATE_DIR="$__MNT/stacks-chainstate-$__NOW"
BITCOIN_DATA_DIR="$__MNT/bitcoin-$__NOW"

echo >&2 "Loaded external config"
