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

func vecToString(i []float64) []string {
	s := make([]string, len(i))
	for n := range i {
		s[n] = strconv.FormatFloat(i[n], 'f', 6, 64)
	}
	return s
}

func readPcapByDevice(pcapFile string, device Device) []string {

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	totals := make([]float64, 15)
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
			ip, _ := ipLayer.(*layers.IPv4)
			if ip.SrcIP.String() == device.IP || ip.DstIP.String() == device.IP {
				totals[0]++ // パケット数
				if ip.SrcIP[0] == 10 && ip.SrcIP.String() != device.IP {
					totals[13]++
				} else if ip.SrcIP[0] != 10 {
					totals[14]++
				}
				if ip.DstIP[0] == 10 && ip.DstIP.String() != device.IP {
					totals[13]++
				} else if ip.DstIP[0] != 10 {
					totals[14]++
				}
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					totals[1]++ // TCPの数
					tcp, _ := tcpLayer.(*layers.TCP)
					// TCPフラグそれぞれの値
					if tcp.URG {
						totals[4]++
					}
					if tcp.ACK {
						totals[5]++
					}
					if tcp.PSH {
						totals[6]++
					}
					if tcp.RST {
						totals[7]++
					}
					if tcp.SYN {
						totals[8]++
					}
					if tcp.FIN {
						totals[9]++
					}

					// ポート番号
					if tcp.SrcPort == 80 {
						totals[10]++
					}
					if tcp.SrcPort == 443 {
						totals[11]++
					}
				}
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					totals[2]++ // UDPの数
					udp, _ := udpLayer.(*layers.UDP)

					// ポート番号
					if udp.SrcPort == 53 {
						totals[12]++
					}
				}
				icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
				if icmpLayer != nil {
					totals[3]++ // ICMPの数
				}
			}
		}
	}

	// 統計値計算
	vec := make([]float64, 14)
	if totals[0] == 0 {
		return vecToString(vec)
	}
	vec[0] = totals[1] / totals[0]
	vec[1] = totals[2] / totals[0]
	vec[2] = totals[3] / totals[0]
	if totals[1] != 0 {
		vec[3] = totals[4] / totals[1]
		vec[4] = totals[5] / totals[1]
		vec[5] = totals[6] / totals[1]
		vec[6] = totals[7] / totals[1]
		vec[7] = totals[8] / totals[1]
		vec[8] = totals[9] / totals[1]

		vec[9] = totals[10] / totals[1]
		vec[10] = totals[11] / totals[1]
	}
	if totals[2] != 0 {
		vec[11] = totals[12] / totals[2]
	}
	if totals[13] != 0 || totals[14] != 0 {
		vec[12] = totals[13] / (totals[13] + totals[14])
		vec[13] = totals[14] / (totals[13] + totals[14])
	}
	return vecToString(vec)
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
