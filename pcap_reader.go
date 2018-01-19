package main

import (
	"io"
	"log"
	"strconv"

	gopacket "github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	pcap "github.com/google/gopacket/pcap"
)

var (
	handle *pcap.Handle
	err    error
)

func portToString(i [65535]int) []string {
	s := make([]string, len(i))
	for n := range i {
		s[n] = strconv.Itoa(i[n])
	}
	return s
}

func readPcap(pcapFile string) []string {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	counter := [65535]int{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}

		// パケットの処理
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				counter[tcp.SrcPort-1]++
				counter[tcp.DstPort-1]++
			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				counter[udp.SrcPort-1]++
				counter[udp.DstPort-1]++
			}
		}
	}
	// counterを[]stringに変換
	return portToString(counter)
}

func pcap2vec(pcaps []string) [][]string {
	var vec [][]string
	for _, pcap := range pcaps {
		data := readPcap(pcap)
		vec = append(vec, data)
	}
	return vec
}

func readPcapByDevice(pcapFile string, device Device) []string {

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var vec []string
	totals := make([]int, 15)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		// パケットの処理
		totals[0]++ // パケット数++
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLay
		if ipLayer != nil {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				// tcp, _ := tcpLayer.(*layers.TCP)

			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				// udp, _ := udpLayer.(*layers.UDP)
			}
		}
	}
	return vec
}

func pcap2csvByDevice(pcaps []string, network Network) {
	for _, device := range network.Devices {
		// deviceごとにpcapからvectorを作成
		var vec [][]string
		for _, pcap := range pcaps {
			vec = append(vec, readPcapByDevice(pcap, device))
		}
		// CSV書き込み
		writeCsv(device.Name+".csv", vec)
	}
}
