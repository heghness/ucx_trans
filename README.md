# ucx_trans
### Transfer file using UCX 

This project is a demo transfer file with the UCX.

First you should install the UCX:

[UCX](http://github.com/openucx/ucx)

compile:

```sh
$ gcc ucp_file_transfer.c  -lucp -lucs -o file_server
$ gcc ucp_file_transfer.c  -lucp -lucs -o file_client
```

Start server:

```sh
$ ./file_server
```

Start client:

```sh
$ ./file_client -f /home/data/MYDATA.fits -s 10.106.21.1
```

> NOTE the `-f` flag sets the path and name of the file that you will transfer by the client.  `-s` is the ip address of the server.

When the file is transfered, you will find it in the `/tmp` directory on the server side.
