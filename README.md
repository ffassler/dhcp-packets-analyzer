# DHCP packets analyzer
Tool to analyse [DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) packets on a network device.
The DHCP packets could be print on standard ouput or/and push to [Zipkin](https://zipkin.io/), a distributed tracing system.

The interaction with Zipkin is realized through the [OpenTracing APIs](https://opentracing.io/).

## Build

Prerequisites
- go 1.11
- pcap library installed on the os

```sh
go get github.com/google/gopacket
go build
```

## Usage

List all devices.
You should have the root privileges to run the program.

```
./dhcp-packets-analyzer

All available devices

enp3s0               : 192.168.1.82,fc00::6,fe80::d847:93b:f438:731a
any                  : <none>
lo                   : 127.0.0.1,::1
docker0              : 172.17.0.1
br-bbac77209949      : 172.18.0.1
nflog                : <none>
nfqueue              : <none>
usbmon1              : <none>
usbmon2              : <none>
usbmon3              : <none>
usbmon4              : <none>

Type -h for usage help.
```

Analyze the packets DHCP on a device.
You must the root privileges to execute this command.

```
./dhcp-packets-analyzer -device enp3s0 -print
Analyze DHCP packets on device enp3s0
Request from 0.0.0.0 / 2c:27:d7:22:4a:88
  Option(MessageType:Request)
  Option(ClientID:[1 44 39 215 34 74 136])
  Option(RequestIP:192.168.1.89)
  Option(Hostname:SITW1605271)
  Option(Unknown:[0 0 0 83 73 84 87 49 54 48 53 50 55 49 46 115 113 117 97 114 101 45 105 116 46 103 114 112])
  Option(ClassID:[77 83 70 84 32 53 46 48])
  Option(ParamsRequest:SubnetMask,Router,DNS,DomainName,RouterDiscovery,StaticRoute,VendorOption,NetBIOSOverTCPNS,NetBIOSOverTCPNodeType,NetBIOSOverTCPScope,DomainSearch,ClasslessStaticRoute,Unknown,Unknown)
  Xid(3211898985)

Reply from 0.0.0.0 / 2c:27:d7:22:4a:88
  Option(MessageType:Ack)
  Option(Timer1:1800)
  Option(Timer2:3150)
  Option(LeaseTime:3600)
  Option(ServerID:192.168.1.227)
  Option(SubnetMask:255.255.255.0)
  Option(Unknown:[0 255 255])
  Option(Router:[192 168 1 253])
  Option(DNS:[192 168 1 227 192 168 1 226])
  Option(DomainName:square-it.grp)
  ClientIP(192.168.1.89)
  Xid(3211898985)
```

Show help

```
./dhcp-packets-analyzer -h                          
Usage of ./dhcp-packets-analyzer:
  -device string
    	device name
  -print
    	Print the analysed DHCP packet to the standard output (default true)
  -zipkin
    	Push the analysed DHCP packet to a zipkin server
  -zipkinEndpoint string
    	Endpoint of zipkin server. Default : http://127.0.0.1:9411/api/v1/spans (default "http://127.0.0.1:9411/api/v1/spans")
```

