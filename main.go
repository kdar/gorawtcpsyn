package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"unsafe"
)

// get the local ip based on our destination ip
func localIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return net.IP{}, err
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	con, err := net.DialUDP("udp", nil, serverAddr)
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return net.IP{}, err

	// tt, err := net.Interfaces()
	// if err != nil {
	//   return nil, err
	// }
	// for _, t := range tt {
	//   aa, err := t.Addrs()
	//   if err != nil {
	//     return nil, err
	//   }
	// ADDR:
	//   for _, a := range aa {
	//     var netip net.IP
	//     switch typ := a.(type) {
	//     case *net.IPNet:
	//       netip = typ.IP.To4()
	//     case *net.IPAddr:
	//       netip = typ.IP
	//     }

	//     if netip == nil || netip[0] == 127 { // loopback address
	//       continue ADDR
	//     }

	//     return netip, nil
	//   }
	// }
	// return nil, errors.New("cannot find local IP address")
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		fmt.Printf("Usage: %s <ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}

	// parse the destination host and port from the command line args
	dstip := net.ParseIP(args[0]).To4()
	dport_, err := strconv.ParseInt(args[1], 10, 16)
	if err != nil {
		panic(err)
	}
	dport := layers.TCPPort(dport_)

	// get our local ip.
	srcip, err := localIP(dstip)
	if err != nil {
		panic(err)
	}

	// Our IPv4 header
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     0, // FIX
		Id:         12345,
		FragOffset: 16384,
		TTL:        64,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0,
		SrcIP:      srcip,
		DstIP:      dstip,
	}

	// Our TCP header
	tcp := &layers.TCP{
		SrcPort:  45677,
		DstPort:  dport,
		Seq:      1105024978,
		Ack:      0,
		SYN:      true,
		Window:   14600,
		Checksum: 0,
		Urgent:   0,
	}
	tcp.DataOffset = uint8(unsafe.Sizeof(tcp))
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true, // automatically compute checksums
	}

	err = ip.SerializeTo(buf, opts)
	if err != nil {
		panic(err)
	}

	err = tcp.SerializeTo(buf, opts)
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		panic(err)
	}

	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip})
	if err != nil {
		panic(err)
	}

	var b []byte
	b = make([]byte, 152)
	n, addr, err := conn.ReadFrom(b)
	if err != nil {
		panic(err)
	}

	if addr.String() == dstip.String() {
		// Decode a packet
		packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			//fmt.Printf("SYN: %v, ACK: %v, RST: %v\n", tcp.SYN, tcp.ACK, tcp.RST)
			if tcp.SYN && tcp.ACK {
				fmt.Printf("Port %d is OPEN\n", dport)
			} else {
				fmt.Printf("Port %d is CLOSED\n", dport)
			}
		}
	}
}
