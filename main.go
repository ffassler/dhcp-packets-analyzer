package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/opentracing/opentracing-go"
	zipkin "github.com/openzipkin-contrib/zipkin-go-opentracing"
	"strings"
)

var (
	spans = make(map[uint32]opentracing.Span)
)

func main() {
	deviceName := flag.String("device", "", "device name")
	printFlag := flag.Bool("print", true, "Print the analysed DHCP packet to the standard output")
	zipkinFlag := flag.Bool("zipkin", false, "Push the analysed DHCP packet to a zipkin server")
	zipkinEndpoint := flag.String("zipkinEndpoint", "http://127.0.0.1:9411/api/v1/spans", "Endpoint of zipkin server. Default : http://127.0.0.1:9411/api/v1/spans")

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
		go readDHCP(handle, *printFlag, *zipkinFlag, *zipkinEndpoint, stop)
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

func readDHCP(handle *pcap.Handle, printFlag bool, zipkinFlag bool, endpoint string, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	var tracer *opentracing.Tracer
	if zipkinFlag {
		tracer = initZipkin(endpoint)
	}
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

			if printFlag {
				fmt.Println(getDHCPPacketInfo(*packet))
			}

			if zipkinFlag {
				pushToZipkin(tracer, *packet)
			}
		}
	}
}

func pushToZipkin(tracer *opentracing.Tracer, packet layers.DHCPv4) {
	xid := packet.Xid

	spanParent, present := spans[xid]

	var span opentracing.Span

	if !present {
		strXid := fmt.Sprint(xid)
		spanParent = (*tracer).StartSpan("dhcp")
		spanParent.SetTag("Xid", strXid)
		spans[xid] = spanParent
	}

	op := packet.Operation
	typePacket := getMessageTypePacket(packet)

	span = (*tracer).StartSpan(typePacket, opentracing.ChildOf(spanParent.Context()))
	span.SetTag("Operation", op)
	span.SetTag("ClientIP", packet.ClientIP.String())
	span.SetTag("ClientMAC", packet.ClientHWAddr.String())
	span.SetTag("YourClientIP", packet.YourClientIP.String())
	span.SetTag("NextServerIP", packet.NextServerIP.String());
	span.SetTag("RelayAgentIP", packet.RelayAgentIP.String())
	for _, option := range packet.Options {
		span.SetTag(option.Type.String(), option.String())
	}

	span.Finish()

	if typePacket == "Ack" {
		spanParent.Finish()
	}
}

func getMessageTypePacket(packet layers.DHCPv4) string {
	for _, option := range packet.Options {
		if option.Type == layers.DHCPOptMessageType {
			return layers.DHCPMsgType(option.Data[0]).String()
		}
	}
	return ""
}

func initZipkin(endpoint string) *opentracing.Tracer {
	
	collector, err := zipkin.NewHTTPCollector(endpoint)
	if err != nil {
		panic(fmt.Sprintf("unable to create Zipkin HTTP collector: %+v\n", err))

	}

	// Create our recorder.
	recorder := zipkin.NewRecorder(collector, true, "0.0.0.0:0", "dhcp-packet-analyzer")

	// Create our tracer.
	tracer, err := zipkin.NewTracer(
		recorder,
		zipkin.ClientServerSameSpan(true),
		zipkin.TraceID128Bit(true),
	)
	if err != nil {
		panic(fmt.Sprintf("unable to create Zipkin tracer: %+v\n", err))
	}

	return &tracer
}

func getDHCPPacketInfo(packet layers.DHCPv4) string {
	info := fmt.Sprintln(packet.Operation.String(), "from", packet.ClientIP.String(), "/", packet.ClientHWAddr.String())

	for _, option := range packet.Options {
		info += fmt.Sprintf("%2s%s\n", "", option.String())
	}

	clientIP := packet.YourClientIP.String()

	if clientIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "YourClientIP", clientIP)
	}

	nextServerIP := packet.NextServerIP.String()

	if nextServerIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "NextServerIP", nextServerIP)
	}

	relayAgentIP := packet.RelayAgentIP.String()

	if relayAgentIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%s(%s)\n", "", "RelayAgentIP", relayAgentIP)
	}

	info += fmt.Sprintf("%2s%s(%v)\n", "", "Xid", packet.Xid)

	return info
}
