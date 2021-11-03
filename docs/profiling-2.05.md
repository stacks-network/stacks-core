## Comparing recent blocks with 2.00 and 2.05 cost rules

1. Run a `stacks-node` or obtain a chainstate from a `stacks-node`
2. Run `exec-block-transactions` command by burn block height with and without 2.05 fork rules:

```
for i in {700000..706801}; do
    ./target/release/blockstack-core exec-block-transactions /tmp/blue-1/data/ $i fork | tee -a /tmp/forked.csv
    ./target/release/blockstack-core exec-block-transactions /tmp/blue-1/data/ $i prefork | tee -a /tmp/preforked.csv
done
```

3. The csv files will contain data like:

```
700000, 2.05, 5045752, 113957, 15, 209992, 3359
700002, 2.05, 3924157, 212, 8, 93853, 994
700003, 2.05, 41184, 2, 4, 11052, 10
700004, 2.05, 1202696, 0, 0, 18464, 308
700000, 2.00, 1225616000, 369437, 15, 462356, 3359
700002, 2.00, 289287000, 16250, 8, 147817, 994
700003, 2.00, 12797000, 2, 4, 11052, 10
700004, 2.00, 51523000, 0, 0, 17799, 308
```

