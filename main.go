package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/opentracing/opentracing-go"
	zipkinot "github.com/openzipkin-contrib/zipkin-go-opentracing"
	"github.com/openzipkin/zipkin-go"
	zipkinhttp "github.com/openzipkin/zipkin-go/reporter/http"
	"net"
	"strings"
)

var (
	spans = make(map[uint32]opentracing.Span)
)

func main() {
	deviceName := flag.String("device", "", "device name")
	printFlag := flag.Bool("print", true, "Print the analysed DHCP packet to the standard output")
	zipkinFlag := flag.Bool("zipkin", false, "Push the analysed DHCP packet to a zipkin server")
	zipkinEndpoint := flag.String("zipkinEndpoint", "http://127.0.0.1:9411/api/v2/spans", "Endpoint of zipkin server. Default : http://127.0.0.1:9411/api/v2/spans")

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
	span.SetTag("NextServerIP", packet.NextServerIP.String())
	span.SetTag("RelayAgentIP", packet.RelayAgentIP.String())
	for _, option := range packet.Options {
		span.SetTag(option.Type.String(), getOptionDataInfo(option))
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

func initZipkin(url string) *opentracing.Tracer {
	reporter := zipkinhttp.NewReporter(url)

	endpoint, err := zipkin.NewEndpoint("dhcp-packet-analyzer", "0.0.0.0:0")
	if err != nil {
		fmt.Println("unable to create local endpoint: %+v\n", err)
	}

	nativeTracer, err := zipkin.NewTracer(reporter, zipkin.WithLocalEndpoint(endpoint), zipkin.WithSharedSpans(true), zipkin.WithTraceID128Bit(true))
	if err != nil {
		fmt.Println("unable to create tracer: %+v\n", err)
	}

	tracer := zipkinot.Wrap(nativeTracer)

	return &tracer
}

func getDHCPPacketInfo(packet layers.DHCPv4) string {
	info := fmt.Sprintln(packet.Operation.String(), "from", packet.ClientIP.String(), "/", packet.ClientHWAddr.String())

	for _, option := range packet.Options {
		info += fmt.Sprintf("%2s%s\n", "", getOptionInfo(option))
	}

	clientIP := packet.YourClientIP.String()

	if clientIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%-15s : %s\n", "", "YourClientIP", clientIP)
	}

	nextServerIP := packet.NextServerIP.String()

	if nextServerIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%-15s : %s\n", "", "NextServerIP", nextServerIP)
	}

	relayAgentIP := packet.RelayAgentIP.String()

	if relayAgentIP != "0.0.0.0" {
		info += fmt.Sprintf("%2s%-15s : %s\n", "", "RelayAgentIP", relayAgentIP)
	}

	info += fmt.Sprintf("%2s%-15s : %v\n", "", "Xid", packet.Xid)

	return info
}

func getOptionInfo(o layers.DHCPOption) string {
	format := "%-15s : %v"
	format2 := "%-15s : "

	switch o.Type {

	case layers.DHCPOptHostname, layers.DHCPOptMeritDumpFile, layers.DHCPOptDomainName, layers.DHCPOptRootPath,
		layers.DHCPOptExtensionsPath, layers.DHCPOptNISDomain, layers.DHCPOptNetBIOSTCPScope, layers.DHCPOptXFontServer,
		layers.DHCPOptXDisplayManager, layers.DHCPOptMessage, layers.DHCPOptDomainSearch: // string
		return fmt.Sprintf(format, o.Type, string(o.Data))

	case layers.DHCPOptMessageType:
		if len(o.Data) != 1 {
			return fmt.Sprintf(format, o.Type, "INVALID")
		}
		return fmt.Sprintf(format, o.Type, layers.DHCPMsgType(o.Data[0]))

	case layers.DHCPOptSubnetMask, layers.DHCPOptServerID, layers.DHCPOptBroadcastAddr,
		layers.DHCPOptSolicitAddr, layers.DHCPOptRequestIP: // net.IP
		if len(o.Data) < 4 {
			return fmt.Sprintf(format, o.Type, "INVALID")
		}
		return fmt.Sprintf(format, o.Type, net.IP(o.Data))

	case layers.DHCPOptT1, layers.DHCPOptT2, layers.DHCPOptLeaseTime, layers.DHCPOptPathMTUAgingTimeout,
		layers.DHCPOptARPTimeout, layers.DHCPOptTCPKeepAliveInt: // uint32
		if len(o.Data) != 4 {
			return fmt.Sprintf(format, o.Type, "INVALID")
		}
		return fmt.Sprintf(format, o.Type,
			uint32(o.Data[0])<<24|uint32(o.Data[1])<<16|uint32(o.Data[2])<<8|uint32(o.Data[3]))

	case layers.DHCPOptParamsRequest:
		buf := &bytes.Buffer{}
		buf.WriteString(fmt.Sprintf(format2, o.Type))
		for i, v := range o.Data {
			buf.WriteString(layers.DHCPOpt(v).String())
			if i+1 != len(o.Data) {
				buf.WriteByte(',')
			}
		}
		return buf.String()

	default:
		return fmt.Sprintf(format, o.Type, o.Data)
	}
}

func getOptionDataInfo(o layers.DHCPOption) string {
	switch o.Type {

	case layers.DHCPOptHostname, layers.DHCPOptMeritDumpFile, layers.DHCPOptDomainName, layers.DHCPOptRootPath,
		layers.DHCPOptExtensionsPath, layers.DHCPOptNISDomain, layers.DHCPOptNetBIOSTCPScope, layers.DHCPOptXFontServer,
		layers.DHCPOptXDisplayManager, layers.DHCPOptMessage, layers.DHCPOptDomainSearch: // string
		return string(o.Data)

	case layers.DHCPOptMessageType:
		if len(o.Data) != 1 {
			return "INVALID"
		}
		return layers.DHCPMsgType(o.Data[0]).String()

	case layers.DHCPOptSubnetMask, layers.DHCPOptServerID, layers.DHCPOptBroadcastAddr,
		layers.DHCPOptSolicitAddr, layers.DHCPOptRequestIP: // net.IP
		if len(o.Data) < 4 {
			return "INVALID"
		}
		return net.IP(o.Data).String()

	case layers.DHCPOptT1, layers.DHCPOptT2, layers.DHCPOptLeaseTime, layers.DHCPOptPathMTUAgingTimeout,
		layers.DHCPOptARPTimeout, layers.DHCPOptTCPKeepAliveInt: // uint32
		if len(o.Data) != 4 {
			return "INVALID"
		}
		return fmt.Sprint(uint32(o.Data[0])<<24 | uint32(o.Data[1])<<16 | uint32(o.Data[2])<<8 | uint32(o.Data[3]))

	case layers.DHCPOptParamsRequest:
		buf := &bytes.Buffer{}
		for i, v := range o.Data {
			buf.WriteString(layers.DHCPOpt(v).String())
			if i+1 != len(o.Data) {
				buf.WriteByte(',')
			}
		}
		return buf.String()

	default:
		return fmt.Sprintf("%v", o.Data)
	}
}
