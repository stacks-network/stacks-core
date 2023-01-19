# A Relay Server

The `relay` server is an HTTP service that has two functions:

- Accepting messages and storing all of them. `POST` method. 
  For example, `curl 'http://127.0.0.1:9776' -X POST -d 'message'`. 
- Returning the messages in the same order as received for each client. 
  For example, `curl 'http://127.0.0.1:9776/?id=alice'`. 

## Start the `relay-server` server

```sh
cargo run --bin relay-server 
```

The default address is `http://127.0.0.1:9776`.

## Integration Test

1. Start the server `cargo run --bit relay-server`
2. Run `./test.sh` in another terminal.
3. Close the server using `Ctrl+C`.
