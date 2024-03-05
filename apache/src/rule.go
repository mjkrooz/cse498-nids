package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net/http"
	"strconv"
)

type Action string
type Protocol string
type Direction string

const (
	Alert      Action = "alert"
	Pass       Action = "pass"
	Drop       Action = "drop"
	Reject     Action = "reject"
	RejectSrc  Action = "rejectsrc"
	RejectDst  Action = "rejectdst"
	RejectBoth Action = "rejectboth"
)

const (
	TCP  Protocol = "tcp"
	UDP  Protocol = "udp"
	ICMP Protocol = "icmp"
	IP   Protocol = "ip"
	HTTP Protocol = "http"
)

const (
	Inbound       Direction = "->"
	Outbound      Direction = "<-"
	Bidirectional Direction = "<>"
)

type RuleAction struct {
	actionType Action
}

type RuleHeader struct {
	protocol        Protocol
	direction       Direction
	source          string
	sourcePort      int
	destination     string
	destinationPort int
}

type RuleOptions struct {
	options map[string]string
}

type Rule struct {
	action  RuleAction
	header  RuleHeader
	options RuleOptions
}

func (rule Rule) encode() string {

	buffer := ""

	buffer = buffer + string(rule.action.actionType)
	buffer = buffer + " " + string(rule.header.protocol)
	buffer = buffer + " " + string(rule.header.source)

	if rule.header.sourcePort == -1 {

		buffer = buffer + " any"
	} else {

		buffer = buffer + " " + strconv.Itoa(rule.header.sourcePort)
	}

	buffer = buffer + " " + string(rule.header.direction)
	buffer = buffer + " " + string(rule.header.destination)

	if rule.header.destinationPort == -1 {

		buffer = buffer + " any" + " ("
	} else {

		buffer = buffer + " " + strconv.Itoa(rule.header.destinationPort) + " ("
	}

	for key, val := range rule.options.options {

		if len(val) == 0 {

			buffer = buffer + key + ";"
		} else {

			buffer = buffer + key + ": " + val + ";"
		}
	}

	buffer = buffer + ")"

	return buffer
}

func (rule Rule) matchHTTPRequest(httpReq *http.Request, raw []byte) bool {

	fmt.Println(string(raw))

	for key, val := range rule.options.options {

		switch key {
		case "content":
			res := performBoyerMoore(httpReq.Host, val)

			if len(res) == 0 {

				return false
			}
		}
	}

	return true
}

func (rule Rule) matchProtocol(packet gopacket.Packet) bool {

	// TCP

	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil && (rule.header.protocol == TCP || rule.header.protocol == HTTP) {

		return false
	} else if tcpLayer != nil {

		// If TCP data was defined, check it.

		tcpPacket := tcpLayer.(*layers.TCP)

		// Source port.

		if rule.header.sourcePort != -1 && int(tcpPacket.SrcPort) != rule.header.sourcePort {

			return false
		}

		// Destination port.

		if rule.header.destinationPort != -1 && int(tcpPacket.DstPort) != rule.header.destinationPort {

			return false
		}

		// HTTP protocol.

		if len(tcpPacket.Payload) != 0 && rule.header.protocol == HTTP {

			reader := bufio.NewReader(bytes.NewReader(tcpPacket.Payload))

			httpReq, err := http.ReadRequest(reader) // TODO: request vs response.

			// If there was an error parsing the HTTP request, assume it is not one, for now.

			if err != nil {

				return false
			}

			// Otherwise, run the HTTP request through the options.

			if !rule.matchHTTPRequest(httpReq, tcpPacket.Payload) {

				return false
			}
		}
	}

	// UDP

	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if udpLayer == nil && rule.header.protocol == UDP {

		return false
	}

	// ICMP

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

	if icmpLayer == nil && rule.header.protocol == ICMP {

		return false
	}

	// IP

	ipLayerv4 := packet.Layer(layers.LayerTypeIPv4)
	ipLayerv6 := packet.Layer(layers.LayerTypeIPv6)

	if (ipLayerv4 == nil && ipLayerv6 == nil) && rule.header.protocol == IP {

		return false
	} else if ipLayerv4 != nil {

		// Check IPv4 addresses, if specified.

		ipPacket := ipLayerv4.(*layers.IPv4)

		if rule.header.source != "any" && ipPacket.SrcIP.String() != rule.header.source {

			return false
		}

		if rule.header.destination != "any" && ipPacket.DstIP.String() != rule.header.destination {

			return false
		}
	} else if ipLayerv6 != nil {

		// Check IPv6 addresses, if specified.

		ipPacket := ipLayerv6.(*layers.IPv6)

		if rule.header.source != "any" && ipPacket.SrcIP.String() != rule.header.source {

			return false
		}

		if rule.header.destination != "any" && ipPacket.DstIP.String() != rule.header.destination {

			return false
		}
	}

	// Nothing failed to match, this protocol is good to go.

	return true
}

func (rule Rule) matchHeader(packet gopacket.Packet) bool {

	// Check the protocol, which includes checking source/destination IPs/ports.

	if !rule.matchProtocol(packet) {

		return false
	}

	// If there is an application layer, run it through the rule options.

	//appLayer := packet.Layer(layers.LayerType)

	// Nothing failed to match, this header is good to go.

	return true
}

func (rule Rule) matchOptions(packet gopacket.Packet) bool {

	return true
}

func (rule Rule) matchRule(packet gopacket.Packet) bool {

	//fmt.Println(rule.options.options["content"])

	// Check if the header matches
	// TODO: matchHeader should return the application layer if possible.s

	if !rule.matchHeader(packet) {

		return false
	}

	// Check if the options match.

	if !rule.matchOptions(packet) {

		return false
	}

	// If no issues occurred, perform the defined action.

	switch rule.action.actionType {
	case Alert:
		fmt.Println("alert")
	}

	return true

	//packet

	//transLayer := packet.TransportLayer()
	////linkLayer := packet.LinkLayer()
	////netLayer := packet.NetworkLayer()
	//appLayer := packet.ApplicationLayer()
	//
	//if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	//	tcp, _ := tcpLayer.(*layers.TCP)
	//	if len(tcp.Payload) != 0 {
	//		reader := bufio.NewReader(bytes.NewReader(tcp.Payload))
	//		httpReq, err := http.ReadRequest(reader)
	//		if err != nil {
	//
	//			//fmt.Println("Could not parse packet as HTTP: " + err.Error())
	//			return false
	//		}
	//		fmt.Println("Successfully parsed packet as HTTP")
	//		fmt.Println(httpReq.Host)
	//		fmt.Println("")
	//	}
	//}
	//
	//if appLayer != nil && len(performBoyerMoore("HTTP", string(appLayer.Payload()))) > 0 {
	//
	//	_, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(transLayer.LayerPayload())))
	//
	//	if err != nil {
	//
	//		//fmt.Println("Could not parse packet as HTTP: " + err.Error())
	//		return false
	//	}
	//	//fmt.Println("Successfully parsed packet as HTTP")
	//	//fmt.Println(output.Host)
	//	//fmt.Println("")
	//
	//	//fmt.Println(string(appLayer.Payload()))
	//
	//	return len(performBoyerMoore(rule.options.options["content"], string(appLayer.Payload()))) > 0
	//}
	//
	//if transLayer != nil && strings.ToLower(transLayer.LayerType().String()) == string(rule.header.protocol) {
	//
	//	//fmt.Println("Found match for protocol: " + transLayer.LayerType().String())
	//	fmt.Println(transLayer.LayerType())
	//	return true
	//}
	//
	///*if linkLayer != nil {
	//
	//	fmt.Println(linkLayer.LayerType())
	//}
	//
	//if netLayer != nil {
	//
	//	fmt.Println(netLayer.LayerType())
	//}*/
	//
	////result := performBoyerMoore(packet, rule.options.options["content"])
	////result := ""
	//
	//if len(packet.Layers()) == 3 {
	//
	//	return false
	//}
	//
	//return false

}
