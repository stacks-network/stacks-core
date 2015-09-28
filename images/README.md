# Docker Image

We also maintain a docker image for blockstored:

```
docker run -it --entrypoint=/bin/bash blockstack/blockstored
```
This currently installs blockstore v0.0.3, which is not the latest release and
we recommend following the
[pip install instructions instead](https://github.com/blockstack/blockstore). 

The docker image comes pre-populated with a snapshot that was processed till a
recent block and you won't have to process all the blocks yourself (which takes
time).