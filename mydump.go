package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	snapshotLen   int32 = 65535
	err           error
	timeout       time.Duration = -1 * time.Second
	handle        *pcap.Handle
	tcpSrcPort    layers.TCPPort
	tcpDestPort   layers.TCPPort
	udpSrcPort    layers.UDPPort
	udpDestPort   layers.UDPPort
	payloadString string = ""
	bpfFilter     string = ""
)

func main() {

	// -i flag is used to specify the network device interface
	var iFlag = flag.String("i", "", "Pass the network device interface for live capture")
	// -r flag is used to read packets from the file
	var rFlag = flag.String("r", "", "Pass the file path to read packets from")
	// -s flag  is used to search for a particular string in a payload
	var sFlag = flag.String("s", "", "Search for string in packet payload")

	flag.Parse()

	// Getting the string to search from the -s flag
	payloadString = *sFlag
	// Storing the BPF string to be applied
	bpfFilter = strings.Join(flag.Args(), " ")

	/*
	If both -i and -r flags are set then packets are read from file else according to flag set
	Else packets are captured live from first available interface
	 */
	if *iFlag!="" || *rFlag!=""{
		if *rFlag!="" {
			readFromFile(*rFlag)
		} else {
			captureLive(*iFlag)
		}
	} else {
		captureLive("")
	}

}

// Check  for a particular device interface or from available interfaces to capture packets
func captureLive(device string) {
	if checkForDevice(device) {
		readLivePackets(device)
	} else {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Panic(err)
		}
		if len(devices)>0 {
			readLivePackets(devices[0].Name)
		} else {
			fmt.Println("No devices available for capturing live packets")
		}
	}
}

// Checks for given device interface name is set of all available network devices
func checkForDevice(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

// Capturing the packets live on a particular device by setting BPF filter if passed
func readLivePackets(device string) {
	handle, error := pcap.OpenLive(device, snapshotLen, true, timeout)
	if error != nil {
		panic(error)
	}else {
		if bpfFilter != "" {
			err := handle.SetBPFFilter(bpfFilter)
			if err != nil {
				panic(err)
			}
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			printDetails(packet)
		}
	}
}

// Packets are read from an existing file with a BPF filter if passed
func readFromFile(filePath string)  {
	if handle, err := pcap.OpenOffline(filePath); err != nil {
		panic(err)
	} else {
		if bpfFilter != "" {
			err := handle.SetBPFFilter(bpfFilter)
			if err != nil {
				panic(err)
			}
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			printDetails(packet)
		}
	}
}

// Printing the details of a packet
func printDetails(packet gopacket.Packet) {

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	applicationLayer := packet.ApplicationLayer()

	// Check if expression to be searched in payload is provided
	if payloadString!="" {
		if ethernetLayer != nil {
			if !strings.Contains(string(ethernetLayer.LayerPayload()), payloadString) {
				return
			}
		} else if ipv4Layer != nil {
			if !strings.Contains(string(ipv4Layer.LayerPayload()), payloadString) {
				return
			}
		} else if applicationLayer!= nil {
			if !strings.Contains(string(applicationLayer.LayerPayload()), payloadString) {
				return
			}
		}
	}

	// Get the timestamp of the packet
	var timeStamp = packet.Metadata().Timestamp.String()
	var timeStampList = strings.Split(timeStamp, " ")
	var timeStampRequired = timeStampList[0] + " " + timeStampList[1]


	// Printing the time
	fmt.Print(timeStampRequired + " ")

	// Get the ethernet frame
	if ethernetLayer != nil {
		ethernetFrame := ethernetLayer.(*layers.Ethernet)
		// Printing the source and destination MAC, ethernet type, packet length
		fmt.Print(ethernetFrame.SrcMAC, " -> ", ethernetFrame.DstMAC, " ")
		// Printing the ethernet type
		fmt.Print("type 0x", strconv.FormatInt(int64(ethernetFrame.EthernetType), 16), " ")
	}

	// Printing the packet length
	fmt.Printf("len %s ", strconv.Itoa(packet.Metadata().Length))

	// Checking for tcp, udp and icmp layer data
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		tcpSrcPort = tcp.SrcPort
		tcpDestPort = tcp.DstPort
		fmt.Print(ipv4Layer.(*layers.IPv4).SrcIP.String() + ":")
		re := regexp.MustCompile("^[0-9]+")
		temp := re.FindString(tcpSrcPort.String())
		fmt.Print(temp + " ")
		fmt.Print(" -> ")
		fmt.Print(ipv4Layer.(*layers.IPv4).DstIP.String() + ":")
		temp = re.FindString(tcpDestPort.String())
		fmt.Print(temp + " ")
		fmt.Print(ipv4Layer.(*layers.IPv4).Protocol.String() + " ")
		if tcp.FIN {
			fmt.Print("FIN" + " ")
		}
		if tcp.SYN {
			fmt.Print("SYN" + " ")
		}
		if tcp.RST {
			fmt.Print("RST" + " ")
		}
		if tcp.PSH {
			fmt.Print("PSH" + " ")
		}
		if tcp.ACK {
			fmt.Print("ACK" + " ")
		}
		if tcp.URG {
			fmt.Print("URG" + " ")
		}
		if tcp.ECE {
			fmt.Print("ECE" + " ")
		}
		if tcp.CWR {
			fmt.Print("CWR" + " ")
		}
		if tcp.NS {
			fmt.Print("NS" + " ")
		}
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		udpSrcPort = udp.SrcPort
		udpDestPort = udp.DstPort
		fmt.Print(ipv4Layer.(*layers.IPv4).SrcIP.String() + ":")
		re := regexp.MustCompile("^[0-9]+")
		temp := re.FindString(udpSrcPort.String())
		fmt.Println(temp + " ")
		fmt.Print(" -> ")
		fmt.Print(ipv4Layer.(*layers.IPv4).DstIP.String() + ":")
		temp = re.FindString(udpDestPort.String())
		fmt.Print(temp + " ")
		fmt.Print(ipv4Layer.(*layers.IPv4).Protocol.String())
	} else if icmpLayer != nil {
		fmt.Print(" ICMP ")
	} else {
		fmt.Print("OTHER")
	}

	fmt.Println()

	// Printing the payload
	 if ethernetLayer!=nil {
	 	fmt.Println(hex.Dump(ethernetLayer.LayerPayload()))
	 } else if ipv4Layer!=nil {
		 fmt.Println(hex.Dump(ipv4Layer.LayerPayload()))
	 } else if applicationLayer!=nil {
		fmt.Printf(hex.Dump(applicationLayer.LayerPayload()))
	}

	 fmt.Println()
}
