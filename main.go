package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
)

func main() {
	deviceName := flag.String("device", "", "device name")
	flag.Parse()

	if *deviceName != "" {
		handle, err := pcap.OpenLive(*deviceName, 65536, true, pcap.BlockForever)
		if err != nil {
			fmt.Println("Error during openning device name", *deviceName, " :", err)
			return
		}
		fmt.Println("Analyze DHCP packets on device", *deviceName)
		stop := make(chan struct{})
		defer handle.Close()
		go readDHCP(handle, stop)
		defer close(stop)
		<-stop
	} else {
		interfaces, err := pcap.FindAllDevs()
		if err == nil {
			fmt.Println("All available devices\n")
			for _, device := range interfaces {
				fmt.Printf("%-20s", device.Name)
				if len(device.Addresses) > 0 {
					addrs := make([]string, 0)
					for _, addr := range device.Addresses {
						addrs = append(addrs, addr.IP.String())
					}
					fmt.Print(" : ", strings.Join(addrs, ","))
				} else {
					fmt.Print(" : <none>")
				}
				fmt.Print("\n")
			}
			fmt.Println("\nType -h for usage help.")
		} else {
			fmt.Println("Error during listing all network devices :", err)
		}
	}
}

func readDHCP(handle *pcap.Handle, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:

			layer := packet.Layer(layers.LayerTypeDHCPv4)

			if layer == nil {
				continue
			}

			packet := layer.(*layers.DHCPv4)

			fmt.Println(getDHCPPacketInfo(*packet))
		}
	}
}

func getDHCPPacketInfo(packet layers.DHCPv4) string {
	info := fmt.Sprintln(packet.Operation.String(), "from", packet.ClientIP.String(), "/", packet.ClientHWAddr.String())

	for _, option := range packet.Options {
		info += fmt.Sprintf("%2s%s\n", "", option.String())
	}

	clientIP := packet.YourClientIP.String()

	if clientIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "ClientIP", clientIP)
	}

	nextServerIP := packet.NextServerIP.String()

	if nextServerIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "ServerIP", nextServerIP)
	}

	relayAgentIP := packet.RelayAgentIP.String()

	if relayAgentIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "RelayAgentIP", relayAgentIP)
	}

	info += fmt.Sprintf("%2s%s(%v)\n", "", "Xid", packet.Xid)

	return info
}
