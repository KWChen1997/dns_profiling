# DNS Parser
- How it works?
	- It will read packets from 127.0.0.1:5960 and send the information to anomaly detector using the following data structure
```c=
struct {
	char destination_addr[16];
	char domain_name[256];
	char domain_name_address[16];
};
```

- How to use?
	- Testing scenario
		- sender/sender
		```sh=
		usage: sender <packet file>
		```

			- This program will send the packet to 127.0.0.1:5960
		- caller/caller
		```sh=
		usage: ./caller
		```

			- This program is a simple version of anomaly detector which only receives data.

	
