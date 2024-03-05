package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"math"
	"os"
	"strconv"
	"time"
)

type shiftTable map[rune]int

func generateShiftTable2(input string) shiftTable {

	inputLength := len(input)

	var skipList shiftTable = make(shiftTable)

	for i, char := range input {

		skipList[char] = int(math.Max(1, float64(inputLength-i-1)))
	}

	fmt.Println(skipList)

	return skipList
}

func generateShiftTable(input string) []int {

	badChars := make([]int, 256) // TODO: only supports ASCII, is this an issue for packets?

	for i := range badChars {

		badChars[i] = -1
	}

	for i, char := range input {

		badChars[char] = i
	}

	return badChars
}

// Adapted from: https://medium.com/@siddharth.21/the-boyer-moore-string-search-algorithm-674906cab162
// Adapted from: https://www.geeksforgeeks.org/boyer-moore-algorithm-for-pattern-searching/
func performBoyerMoore(input string, within string) []int {

	inputLength := len(input)
	withinLength := len(within)
	skipList := generateShiftTable(input)

	//i := inputLength - 1 // Starting at the end of the search string.

	result := make([]int, 0)

	shift := 0

	for shift <= withinLength-inputLength {

		j := inputLength - 1

		for j >= 0 && input[j] == within[shift+j] {

			j = j - 1
		}

		if j < 0 {

			//fmt.Printf("Pattern found at index %d\n", shift)

			result = append(result, shift)

			if shift+inputLength < withinLength {

				shift = shift + inputLength - skipList[rune(within[shift+inputLength])]
			} else {

				shift++
			}

		} else {

			shift += int(math.Max(1, float64(j-skipList[rune(within[shift+j])])))
		}
	}

	return result
}

func listDevices() []string {
	// Find all devices
	rawDevices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information

	devices := make([]string, 0)

	fmt.Println("Devices found:")

	for id, device := range rawDevices {
		fmt.Println("Description: ", device.Description+" ("+device.Name+")", "ID: ", id)

		devices = append(devices, device.Name)

		//fmt.Println("Description: ", device.Description)
		//fmt.Println("Devices addresses: ", device.Description)
		//for _, address := range device.Addresses {
		//	fmt.Println("- IP address: ", address.IP)
		//	fmt.Println("- Subnet mask: ", address.Netmask)
		//}
	}

	return devices
}

func checkPacket(rules []Rule, packet gopacket.Packet) {

	//fmt.Println(packet.String())

	for _, rule := range rules {

		//fmt.Println("Attempting to match rule: " + rule.encode())
		//fmt.Println("With packet: ---- " + packet.String())

		if rule.matchRule(packet) {

			fmt.Println("Matched rule: " + rule.encode())
			fmt.Println("With packet: ---- " + packet.String())
		} else {

			//fmt.Println("Match failed")
		}

		//fmt.Println("")
		//fmt.Println("======================================================")
		//fmt.Println("")
	}
}

func openPacketListener(deviceName string, rules []Rule) {
	device, err := pcap.OpenLive(deviceName, 65535, false, 1*time.Second)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Opened device: " + deviceName)
	}
	defer device.Close()

	packetSource := gopacket.NewPacketSource(device, device.LinkType())

	for packet := range packetSource.Packets() {
		// Process packet here

		checkPacket(rules, packet)
	}

	/*fmt.Println("\nName: ", device.Name)
	fmt.Println("Description: ", device.Description)
	fmt.Println("Devices addresses: ", device.Description)
	for _, address := range device.Addresses {
		fmt.Println("- IP address: ", address.IP)
		fmt.Println("- Subnet mask: ", address.Netmask)
	}*/
}

func main() {

	// Parse rules for Suricata.

	rules := parseSuricataRules("emerging-exploit.rules")

	// Listen for packets and see if any match the existing rules.

	devices := listDevices()

	args := os.Args[1:]

	if len(args) == 0 {

		fmt.Println("\nMissing required device name, choose one of the above by supplying the ID as an argument to the executable.\n")
		os.Exit(5)
	}
	// \Device\NPF_{098785A7-5FA4-4843-A804-00C5EDE5B82F}

	deviceID, err := strconv.Atoi(args[0])

	if err != nil || deviceID >= len(devices) || deviceID < 0 {

		fmt.Println("Invalid device ID")
		os.Exit(6)
	}

	openPacketListener(devices[deviceID], rules)

	fmt.Println("Done")
}
