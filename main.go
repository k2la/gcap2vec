package main

import (
	"fmt"
	"io"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
