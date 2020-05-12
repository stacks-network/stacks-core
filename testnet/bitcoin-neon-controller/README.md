# Neon master node

Neon master node is responsible for:
- forwarding authorized RPC calls (such as `sendrawtransaction`, `importaddress` and `listunspent`) to a centralized bitcoind chain, running in regtest mode.
- mining bitcoin blocks (every 7 secs)
- seed BTC faucet.
