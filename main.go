package main

import (
  "code.google.com/p/gopacket"
  "code.google.com/p/gopacket/layers"
  "errors"
  "flag"
  "fmt"
  "net"
  "os"
  "strconv"
  "unsafe"
)

// get the local ip. very naive
func localIP() (net.IP, error) {
  tt, err := net.Interfaces()
  if err != nil {
    return nil, err
  }
  for _, t := range tt {
    aa, err := t.Addrs()
    if err != nil {
      return nil, err
    }
    for _, a := range aa {
      ipnet, ok := a.(*net.IPNet)
      if !ok {
        continue
      }
      v4 := ipnet.IP.To4()
      if v4 == nil || v4[0] == 127 { // loopback address
        continue
      }
      return v4, nil
    }
  }
  return nil, errors.New("cannot find local IP address")
}

func main() {
  flag.Parse()
  args := flag.Args()
  if len(args) != 2 {
    fmt.Printf("Usage: %s <ip> <port>\n", os.Args[0])
    os.Exit(-1)
  }

  // get our local ip. this might not be the right address
  srcip, err := localIP()
  if err != nil {
    panic(err)
  }

  // parse the destination host and port from the command line args
  dstip := net.ParseIP(args[0]).To4()
  dport_, err := strconv.ParseInt(args[1], 10, 16)
  if err != nil {
    panic(err)
  }
  dport := layers.TCPPort(dport_)

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
  b = make([]byte, 52)
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
