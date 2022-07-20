# It's working!

cache hits take nanoseconds, while cache misses take microseconds!

```
7339 INFO [1658345227.461206] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=59759, time_cost=9.56µs
7340 INFO [1658345227.461220] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=63745, time_cost=7.324µs
7341 INFO [1658345227.461226] [src/chainstate/stacks/index/storage.rs:160] [chains-coordinator] get_block_hash_caching: result=hit, id=77453, time_cost=79ns
7342 INFO [1658345227.461228] [src/chainstate/stacks/index/storage.rs:160] [chains-coordinator] get_block_hash_caching: result=hit, id=76941, time_cost=46ns
7343 INFO [1658345227.461238] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=65580, time_cost=7.654µs
7344 INFO [1658345227.461251] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=68751, time_cost=6.842µs
7345 INFO [1658345227.461264] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=73904, time_cost=7.688µs
7346 INFO [1658345227.461270] [src/chainstate/stacks/index/storage.rs:160] [chains-coordinator] get_block_hash_caching: result=hit, id=76511, time_cost=46ns
7347 INFO [1658345227.461279] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=76867, time_cost=7.2µs
7348 INFO [1658345227.461293] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=54613, time_cost=7.278µs
7349 INFO [1658345227.461306] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=73458, time_cost=7.12µs
7350 INFO [1658345227.461312] [src/chainstate/stacks/index/storage.rs:160] [chains-coordinator] get_block_hash_caching: result=hit, id=77449, time_cost=43ns
7351 INFO [1658345227.461321] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=68660, time_cost=6.971µs
7352 INFO [1658345227.461338] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=73775, time_cost=10.218µs
7353 INFO [1658345227.461348] [src/chainstate/stacks/index/storage.rs:160] [chains-coordinator] get_block_hash_caching: result=hit, id=77455, time_cost=58ns
7354 INFO [1658345227.461362] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=67602, time_cost=11.206µs
7355 INFO [1658345227.461383] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=64758, time_cost=10.333µs
7356 INFO [1658345227.461402] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=58012, time_cost=9.869µs
7357 INFO [1658345227.461420] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=69439, time_cost=9.537µs
7358 INFO [1658345227.461434] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=72850, time_cost=7.529µs
7359 INFO [1658345227.461449] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=50171, time_cost=8.962µs
7360 INFO [1658345227.461479] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=48620, time_cost=19.666µs
7361 INFO [1658345227.461499] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=63607, time_cost=9.789µs
7362 INFO [1658345227.461517] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=64732, time_cost=8.965µs
7363 INFO [1658345227.461537] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=71049, time_cost=10.277µs
7364 INFO [1658345227.461551] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=65656, time_cost=6.927µs
7365 INFO [1658345227.461565] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=72320, time_cost=8.113µs
7366 INFO [1658345227.461581] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=49014, time_cost=9.29µs
7367 INFO [1658345227.461594] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=74839, time_cost=7.647µs
7368 INFO [1658345227.461607] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=76901, time_cost=7.055µs
7369 INFO [1658345227.461621] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=63994, time_cost=7.344µs
7370 INFO [1658345227.461635] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=70456, time_cost=7.298µs
7371 INFO [1658345227.461648] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=74581, time_cost=7.591µs
7372 INFO [1658345227.461662] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=51911, time_cost=7.235µs
7373 INFO [1658345227.461676] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=46962, time_cost=8.227µs
7374 INFO [1658345227.461689] [src/chainstate/stacks/index/storage.rs:144] [chains-coordinator] get_block_hash_caching: result=miss, id=69931, time_cost=7.24µs
```
