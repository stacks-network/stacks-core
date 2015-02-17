# Usage

To start blockstore:

```
$ blockstored start
```

To stop blockstore:

```
$ blockstored stop
```

To register a key-value pair, first preorder the name:

```
$ blockstore-cli preorder swiftonsecurity <privatekey>
```

Then, after the preorder transaction has made it into a block and been accepted by the blockstore nodes, you are free to register the name:

```
$ blockstore-cli register swiftonsecurity <privatekey>
```

Finally, after the register transaction made it into the block and been accepted by the blockstore nodes, you are free to update and transfer the name:

```
$ blockstore-cli update swiftonsecurity <data> <privatekey>
$ blockstore-cli transfer swiftonsecurity <newowner> <privatekey>
```

To perform a lookup on a name:

```
$ blockstore-cli lookup swiftonsecurity
```