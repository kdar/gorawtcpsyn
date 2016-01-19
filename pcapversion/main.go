// Windows doesn't allow raw TCP sockets. So I attempt to do a SYN
// scan with pcap.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
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
	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return net.IP{}, err
}

// Sends an ARP request packet to determine the MAC address of an IP
func remoteMac(dev string, srcmac net.HardwareAddr, srcip, dstip net.IP) (net.HardwareAddr, error) {
	var dstmac net.HardwareAddr

	eth := &layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, //arp request
		SourceHwAddress:   srcmac,
		SourceProtAddress: srcip,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstip,
	}

	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true, // automatically compute checksums
			FixLengths:       true,
		},
		eth, arp,
	)
	if err != nil {
		return dstmac, err
	}

	handle, err := pcap.OpenLive(`rpcap://`+dev, 65535, true, time.Second*1)
	if err != nil {
		return dstmac, err
	}
	defer handle.Close()

	var wg sync.WaitGroup

	handle.SetBPFFilter(fmt.Sprintf("arp and ether host %s", srcmac.String()))
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	macchan := make(chan net.HardwareAddr, 1)

	wg.Add(1)
	go func() {
		stop := false

		go func() {
			<-time.After(time.Second * 2)
			stop = true
		}()

		for {
			if stop {
				break
			}

			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				//log.Println("Error:", err)
				continue
			}

			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp_, _ := arpLayer.(*layers.ARP)

				if bytes.Equal(arp_.SourceProtAddress, dstip) && arp_.Operation == 2 {
					macchan <- arp_.SourceHwAddress
					break
				}
			}
		}

		wg.Done()
	}()

	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return dstmac, err
	}

	wg.Wait()

	dstmac = <-macchan
	return dstmac, nil
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		log.Printf("Usage: %s <ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}

	// parse the destination host and port from the command line args
	dstip := net.ParseIP(args[0]).To4()
	dport_, err := strconv.ParseInt(args[1], 10, 16)
	if err != nil {
		log.Fatal(err)
	}
	dport := layers.TCPPort(dport_)
	sport := layers.TCPPort(5000)

	// get our local ip.
	srcip, err := localIP(dstip)
	if err != nil {
		log.Fatal(err)
	}

	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	dev := ""
	for _, d := range devs {
		for _, a := range d.Addresses {
			if bytes.Equal(a.IP, srcip) {
				dev = d.Name
			}
		}
		// if d.Description == "Realtek PCIe GBE Family Controller" {
		//   fmt.Println(d.Name)
		//   dev = d.Name
		// }

		// fmt.Println(dev.Description)
	}

	if dev == "" {
		log.Fatal("Could not find the appropriate adapter device")
	}

	srcmac, err := localMac(dev)
	if err != nil {
		log.Fatal(err)
	}

	dstmac, err := remoteMac(dev, srcmac, srcip, dstip)
	if err != nil {
		log.Fatal(err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       dstmac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Our IPv4 header
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     20, // FIX
		Id:         2,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0, //16384,
		TTL:        3, //64,
		Protocol:   layers.IPProtocolTCP,
		Checksum:   0,
		SrcIP:      srcip,
		DstIP:      dstip,
	}

	// Our TCP header
	tcp := &layers.TCP{
		SrcPort:  sport,
		DstPort:  dport,
		Seq:      0,
		Ack:      0,
		SYN:      true,
		Window:   64240,
		Checksum: 0,
		Urgent:   0,
	}
	tcp.DataOffset = 5 // uint8(unsafe.Sizeof(tcp))
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true, // automatically compute checksums
			FixLengths:       true,
		},
		eth, ip, tcp,
	)
	if err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive(`rpcap://`+dev, 65535, true, time.Second*1)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var wg sync.WaitGroup

	handle.SetBPFFilter(fmt.Sprintf("tcp and host %s and host %s and port %d and port %d", srcip.String(), dstip.String(), sport, dport))
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	wg.Add(1)
	go func() {
		stop := false

		go func() {
			<-time.After(time.Second * 2)
			stop = true
		}()

		for {
			if stop {
				break
			}

			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				//log.Println("Error:", err)
				continue
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SrcPort == dport && tcp.DstPort == sport {
					if tcp.SYN && tcp.ACK {
						fmt.Printf("Port %d is OPEN\n", dport_)
					} else {
						fmt.Printf("Port %d is CLOSED\n", dport_)
					}
					break
				}
				//fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
			}
		}

		wg.Done()
	}()

	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}
