package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
)

var (
	pcapFile string = "10.144.0.0-2018-01-05-2100.pcap"
	handle   *pcap.Handle
	err      error
)

func printPacketInfo(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("[*] Ethernet Layer")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("\t%s\n", ethernetPacket.SrcMAC)
		fmt.Printf("\t%s\n", ethernetPacket.DstMAC)
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("[*] IPv4 layer")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("\t%s -> %s\n", ip.SrcIP, ip.DstIP)
		fmt.Printf("\tProtocol: %s\n", ip.Protocol)
		fmt.Printf("\tIHL: %d\n", ip.IHL)
		fmt.Printf("\tTOS: %d\n", ip.TOS)
		fmt.Printf("\tLength: %d\n", ip.Length)
		fmt.Printf("\tId: %d\n", ip.Id)
		fmt.Printf("\tFlags: %s\n", ip.Flags)
		fmt.Printf("\tFragOffset: %d\n", ip.FragOffset)
		fmt.Printf("\tTTL: %d\n", ip.TTL)
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		if tcp.SYN {
			fmt.Println("[*] TCP Layer")
			fmt.Printf("\t%s:%d -> %s:%d\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			fmt.Printf("\tSeq: %d\n", tcp.Seq)
			fmt.Printf("\tAck: %d\n", tcp.Ack)
			fmt.Printf("\tDataOffset: %d\n", tcp.DataOffset)
			fmt.Printf("\tWindow: %d\n", tcp.Window)
			fmt.Printf("\tChecksum: %d\n", tcp.Checksum)
		}
	}

}

func main() {
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		printPacketInfo(packet)
		// break
	}
}
