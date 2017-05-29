# Basic Sniffer
## Info
This little program is the program assignment of Internet Security in NUAA, 2017. It's written in Linux raw socket to capture the Ethernet traffics. By setting the promiscuous mode in the network interface, it can get the whole network's packets, and then display the key infomation of packets on the shell. Provide a file name argument, it can record the raw bytes into the file.

## Usage
```
sudo ./sniffer [log_file]
```

## TODO
- Add a filter
 
