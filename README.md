gorawtcpsyn
===========

Simple go program that will test if a port is open by sending a TCP SYN packet to it. Demonstrates how to use RAW IP sockets in Go 1.x+.

### Usage

gorawtcpsyn **ip** **port**

##### Example

gorawtcpsyn 192.168.0.2 5656

### Note

Must run as root. This program is purposefully stupid/easy/dumb/simple.

### Other examples of raw socket usage in Go

The authors of [gopacket](https://github.com/google/gopacket/) (which this example uses), also has a few other examples like an ARP scanner and a SYN scanner in his repository [here](https://github.com/google/gopacket/tree/master/examples).
