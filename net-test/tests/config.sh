# local config
__ROOT="$(realpath "$(pwd)"/..)"
__ETC="$__ROOT/etc"
__MNT="$__ROOT/mnt"
__BIN="$__ROOT/bin"
__NOW="$(date +%s)"

set +u

if [ -z "$STACKS_MASTER_NAME" ]; then 
   STACKS_MASTER_NAME="stacks-node-master"
fi
if [ -z "$STACKS_MINER_NAME" ]; then
   STACKS_MINER_NAME="stacks-node-miner"
fi
if [ -z "$STACKS_FOLLOWER_NAME" ]; then
   STACKS_FOLLOWER_NAME="stacks-node-follower"
fi

set -u

BITCOIN_CONF="$__ETC/bitcoin.conf"
BITCOIN_DATA_DIR="$__MNT/bitcoin-$__NOW"
BITCOIN_PUBLIC_IP="127.0.0.1"
BITCOIN_LOGFILE="$__MNT/bitcoin.log"

BITCOIN_CONTROLLER_CONF="$__ETC/bitcoin-neon-controller.toml"
BITCOIN_CONTROLLER_LOGFILE="$__MNT/bitcoin-neon-controller.log"

STACKS_MASTER_CONF_IN="$__ETC/stacks-master.toml.in"
STACKS_MASTER_CONF="$__ETC/conf-$STACKS_MASTER_NAME.toml"
STACKS_MASTER_CHAINSTATE_DIR="$__MNT/chainstate-$STACKS_MASTER_NAME"
STACKS_MASTER_LOGFILE="$__MNT/log-$STACKS_MASTER_NAME.log"
STACKS_MASTER_PUBLIC_IP="127.0.0.1"
STACKS_MASTER_P2P_PORT="20444"
STACKS_MASTER_DENY_NODES=""
STACKS_MASTER_IS_MINER="true"
STACKS_MASTER_DISABLE_INBOUND_HANDSHAKES="false"
STACKS_MASTER_DISABLE_INBOUND_WALKS="false"
STACKS_MASTER_MINE_MICROBLOCKS="true"
STACKS_MASTER_WAIT_FOR_MICROBLOCKS="5000"
STACKS_MASTER_MICROBLOCK_FREQUENCY="1000"
STACKS_MASTER_MAX_MICROBLOCKS="10"

STACKS_MINER_CONF_IN="$__ETC/stacks-miner.toml.in"
STACKS_MINER_CONF="$__ETC/conf-$STACKS_MINER_NAME.toml"
STACKS_MINER_CHAINSTATE_DIR="$__MNT/chainstate-$STACKS_MINER_NAME"
STACKS_MINER_PUBLIC_IP="127.0.0.1"
STACKS_MINER_DENY_NODES=""
STACKS_MINER_RPC_PORT=21443
STACKS_MINER_P2P_PORT=21444
STACKS_MINER_LOGFILE="$__MNT/log-$STACKS_MINER_NAME.log"
STACKS_MINER_BOOTSTRAP_IP="$STACKS_MASTER_PUBLIC_IP"
STACKS_MINER_BOOTSTRAP_PORT="$STACKS_MASTER_P2P_PORT"
STACKS_MINER_DISABLE_INBOUND_HANDSHAKES="false"
STACKS_MINER_DISABLE_INBOUND_WALKS="false"
STACKS_MINER_MINE_MICROBLOCKS="true"
STACKS_MINER_WAIT_FOR_MICROBLOCKS="5000"
STACKS_MINER_MICROBLOCK_FREQUENCY="1000"
STACKS_MINER_MAX_MICROBLOCKS="10"

STACKS_FOLLOWER_CONF_IN="$__ETC/stacks-follower.toml.in"
STACKS_FOLLOWER_CONF="$__ETC/conf-$STACKS_FOLLOWER_NAME.toml"
STACKS_FOLLOWER_CHAINSTATE_DIR="$__MNT/chainstate-$STACKS_FOLLOWER_NAME"
STACKS_FOLLOWER_PUBLIC_IP="127.0.0.1"
STACKS_FOLLOWER_DENY_NODES=""
STACKS_FOLLOWER_P2P_PORT=31443
STACKS_FOLLOWER_RPC_PORT=31444
STACKS_FOLLOWER_LOGFILE="$__MNT/log-$STACKS_FOLLOWER_NAME.log"
STACKS_FOLLOWER_BOOTSTRAP_IP="$STACKS_MASTER_PUBLIC_IP"
STACKS_FOLLOWER_BOOTSTRAP_PORT="$STACKS_MASTER_P2P_PORT"
STACKS_FOLLOWER_DISABLE_INBOUND_HANDSHAKES="false"
STACKS_FOLLOWER_DISABLE_INBOUND_WALKS="false"

FAUCET_LOGFILE="$__MNT/faucet.log"
FAUCET_PUBLIC_IP="127.0.0.1"
FAUCET_PORT=8080
FAUCET_URL="http://$FAUCET_PUBLIC_IP:$FAUCET_PORT"

PROCESS_EXIT_AT_BLOCK_HEIGHT=100

CONFIG_MODE=""

fs_setup() {
   local ETC="$1"
   local MNT="$2"

   __ETC="$ETC"
   __MNT="$MNT"
   return 0
}

set_mode() {
   CONFIG_MODE="$1"
   clear_bans
   clear_bootstrap
   clear_nat
}

master_config() {
   local NAME="$1"
   local PUBLIC_IP="$2"
   local IS_MINER="$3"

   STACKS_MASTER_NAME="$NAME"
   STACKS_MASTER_CONF="$__ETC/conf-$NAME.toml"
   STACKS_MASTER_CHAINSTATE_DIR="$__MNT/chainstate-$NAME"
   STACKS_MASTER_LOGFILE="$__MNT/log-$NAME.log"
   STACKS_MASTER_PUBLIC_IP="$PUBLIC_IP"
   STACKS_MASTER_IS_MINER="$IS_MINER"
   STACKS_MASTER_MINE_MICROBLOCKS="$IS_MINER"

   set_mode master
   return 0
}

miner_config() {
   local NAME="$1"
   local RPC_PORT="$2"
   local P2P_PORT="$3"

   STACKS_MINER_NAME="$NAME"
   STACKS_MINER_CONF="$__ETC/conf-$NAME.toml"
   STACKS_MINER_CHAINSTATE_DIR="$__MNT/chainstate-$NAME"
   STACKS_MINER_RPC_PORT="$RPC_PORT"
   STACKS_MINER_P2P_PORT="$P2P_PORT"
   STACKS_MINER_LOGFILE="$__MNT/log-$NAME.log"

   set_mode miner
   return 0
}

follower_config() {
   local NAME="$1"
   local RPC_PORT="$2"
   local P2P_PORT="$3"
   
   STACKS_FOLLOWER_NAME="$NAME"
   STACKS_FOLLOWER_CONF="$__ETC/conf-$NAME.toml"
   STACKS_FOLLOWER_CHAINSTATE_DIR="$__MNT/chainstate-$NAME"
   STACKS_FOLLOWER_RPC_PORT="$RPC_PORT"
   STACKS_FOLLOWER_P2P_PORT="$P2P_PORT"
   STACKS_FOLLOWER_LOGFILE="$__MNT/log-$NAME.log"

   set_mode follower
   return 0
}

ban_peer() {
   local IP="$1"
   local PORT="$2"
   case "$CONFIG_MODE" in
      master)
         STACKS_MASTER_DENY_NODES="$IP:$PORT,$STACKS_MASTER_DENY_NODES"
         ;;
      miner)
         STACKS_MINER_DENY_NODES="$IP:$PORT,$STACKS_MINER_DENY_NODES"
         ;;
      follower)
         STACKS_FOLLOWER_DENY_NODES="$IP:$PORT,$STACKS_FOLLOWER_DENY_NODES"
         ;;
   esac
   return 0
}

set_nat() {
   local NAT="$1"
   case "$CONFIG_MODE" in
      master)
         STACKS_MASTER_DISABLE_INBOUND_HANDSHAKES="$NAT"
         ;;
      miner)
         STACKS_MINER_DISABLE_INBOUND_HANDSHAKES="$NAT"
         ;;
      follower)
         STACKS_FOLLOWER_DISABLE_INBOUND_HANDSHAKES="$NAT"
         ;;
   esac
   return 0
}

set_inbound_walks() {
   local ALLOW_INBOUND_WALKS="$1"
   local INBOUND_WALKS=""
   if [[ "$ALLOW_INBOUND_WALKS" = "true" ]]; then
      INBOUND_WALKS="false"
   else
      INBOUND_WALKS="true"
   fi

   case "$CONFIG_MODE" in
      master)
         STACKS_MASTER_DISABLE_INBOUND_WALKS="$INBOUND_WALKS"
         ;;
      miner)
         STACKS_MINER_DISABLE_INBOUND_WALKS="$INBOUND_WALKS"
         ;;
      follower)
         STACKS_FOLLOWER_DISABLE_INBOUND_WALKS="$INBOUND_WALKS"
         ;;
   esac
   return 0
}

bootstrap() {
   local IP="$1"
   local PORT="$2"
   case "$CONFIG_MODE" in
      miner)
         STACKS_MINER_BOOTSTRAP_IP="$IP"
         STACKS_MINER_BOOTSTRAP_PORT="$PORT"
         ;;
      follower)
         STACKS_FOLLOWER_BOOTSTRAP_IP="$IP"
         STACKS_FOLLOWER_BOOTSTRAP_PORT="$PORT"
         ;;
   esac
   return 0
}

clear_bans() {
   case "$CONFIG_MODE" in
      master)
         STACKS_MASTER_DENY_NODES=""
         ;;
      miner)
         STACKS_MINER_DENY_NODES=""
         ;;
      follower)
         STACKS_FOLLOWER_DENY_NODES=""
         ;;
   esac
   return 0
}

clear_bootstrap() {
   case "$CONFIG_MODE" in
      miner)
         STACKS_MINER_BOOTSTRAP_IP="$STACKS_MASTER_PUBLIC_IP"
         STACKS_MINER_BOOTSTRAP_PORT="$STACKS_MASTER_P2P_PORT"
         ;;
      follower)
         STACKS_FOLLOWER_BOOTSTRAP_IP="$STACKS_MASTER_PUBLIC_IP"
         STACKS_FOLLOWER_BOOTSTRAP_PORT="$STACKS_MASTER_P2P_PORT"
         ;;
   esac
   return 0
}

clear_nat() {
   case "$CONFIG_MODE" in
      master)
         STACKS_MASTER_DISABLE_INBOUND_HANDSHAKES="false"
         ;;
      miner)
         STACKS_MINER_DISABLE_INBOUND_HANDSHAKES="false"
         ;;
      follower)
         STACKS_FOLLOWER_DISABLE_INBOUND_HANDSHAKES="false"
         ;;
   esac
   return 0
}

clear_inbound_walks() {
   case "$CONFIG_MODE" in
      master)
         STACKS_MASTER_DISABLE_INBOUND_WALKS="false"
         ;;
      miner)
         STACKS_MINER_DISABLE_INBOUND_WALKS="false"
         ;;
      follower)
         STACKS_FOLLOWER_DISABLE_INBOUND_WALKS="false"
         ;;
   esac
   return 0
}
