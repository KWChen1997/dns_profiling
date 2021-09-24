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
	```c=
int dump_packet(void *data, size_t data_len);
/*
 * purpose: get the information inside the packet
 * data: the packet
 * data_len: the packet size
 * */
	```

	
