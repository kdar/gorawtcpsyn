gorawtcpsyn
===========

This is a version that works with Windows. A little modification could make it work with any platform that has pcap.

This version is slightly more complicated as it knows how to get its local MAC address, get a remote MAC address using ARP packets, and uses pcap to packet sniff.
I haven't implemented it being able to send packets outside the network (getting gateway ip).

It's not as fast as the main version, which can probably be fixed if I put more time into it. It also is dumb in that it doesn't check the local ARP cache to see
if it knows the remote MAC already.

This is just a proof of concept for other people to learn off of.

### Usage

gorawtcpsyn **ip** **port**

##### Example

gorawtcpsyn 192.168.0.2 5656

### Note

Must run as root. 