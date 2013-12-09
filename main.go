package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// get the local ip based on our destination ip
func localIP(dstip net.IP) net.IP {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		panic(err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP
		}
	}
	panic("could not get local ip: " + err.Error())
}

func main() {
	if len(os.Args) != 3 {
		log.Printf("Usage: %s <ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}
	log.Println("starting")

	// parse the destination host and port from the command line os.Args
	dstip := net.ParseIP(os.Args[1]).To4()
	var dport layers.TCPPort
	if d, err := strconv.ParseInt(os.Args[2], 10, 16); err != nil {
		panic(err)
	} else {
		dport = layers.TCPPort(d)
	}

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP: localIP(dstip),
		DstIP: dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort:  45677,
		DstPort:  dport,
		Seq:      1105024978,
		SYN:      true,
		Window:   14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		panic(err)
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		panic(err)
	}
	log.Println("writing request")
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		panic(err)
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		panic(err)
	}

	for {
		b := make([]byte, 4096)
		log.Println("reading from conn")
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			log.Println("error reading packet: ", err)
			return
		} else if addr.String() == dstip.String() {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.SYN && tcp.ACK {
					log.Printf("Port %d is OPEN\n", dport)
				} else {
					log.Printf("Port %d is CLOSED\n", dport)
				}
			}
			return
		} else {
			log.Printf("Got packet not matching addr")
		}
	}
}
