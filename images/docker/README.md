# Docker Images

On Debian or Ubuntu, you can install docker:

> $ sudo apt-get install docker.io

Go to the appropriate directory e.g., 

```
$ cd docker/api
$ sudo docker build --no-cache . -t blockstack-core-api
```

This will output something like:
> Successfully built \<docker_image_id\>

You can boot into the respective image:
``` 
$ sudo docker run -it --entrypoint=/bin/bash <docker_image_id>
```