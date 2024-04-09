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

// Adapted from: https://www.geeksforgeeks.org/rabin-karp-algorithm-for-pattern-searching/
func performRabinKarp(input string, within string, primeNumber int) []int {

	var result []int = make([]int, 0)

	inputLength := len(input)   // M
	withinLength := len(within) // N

	// "Hash value for input"

	p := 0

	// "Hash value for within"

	t := 0
	h := 1

	// "The value of h would be `pow(256, inputLength - 1) % primeNumber`"

	for i := 0; i < inputLength-1; i++ {

		h = (h * 256) % primeNumber
	}

	// "Calculate the hash value of pattern and first window of text"

	for i := 0; i < inputLength; i++ {

		p = (256*p + int(rune(input[i]))) % primeNumber
		t = (256*t + int(rune(within[i]))) % primeNumber
	}

	// "Slide the pattern over text one by one"

	j := 0

	for i := 0; i <= withinLength-inputLength; i++ {

		// "Check the hash values of current window of text and pattern.
		// If the hash values match then only check for characters one
		// by one"

		if p == t {

			// "Check for characters one by one"

			for j = 0; j < inputLength; j++ {

				if within[i+j] != input[j] {

					break
				}
			}

			if j == inputLength {

				result = append(result, i)
			}
		}

		// "Calculate hash value for next window of text:
		// Remove leading digit, add trailing digit"

		if i < withinLength-inputLength {

			t = (256*(t-int(rune(within[i]))*h) + int(rune(within[i+inputLength]))) % primeNumber

			// "We might get negative value of t, converting it to positive"

			if t < 0 {

				t = t + primeNumber
			}
		}
	}

	return result
}

func generateLPSArray(input string) []int {

	inputLength := len(input)
	result := make([]int, inputLength)

	prevLength := 0
	i := 1

	result[0] = 0

	for i < inputLength {

		if input[i] == input[prevLength] {

			prevLength++
			result[i] = prevLength
			i++
		} else {

			if prevLength != 0 {

				prevLength = result[prevLength-1]
			} else {

				result[i] = prevLength
				i++
			}
		}
	}

	return result
}

// Adapted from: https://www.geeksforgeeks.org/kmp-algorithm-for-pattern-searching/
func performKnuthMorrisPratt(input string, within string) []int {

	result := make([]int, 0)

	inputLength := len(input)
	withinLength := len(within)

	lps := generateLPSArray(input)

	i := 0 // Index in `within`
	j := 0 // Input in `input`

	for (withinLength - i) >= (inputLength - j) {

		if input[j] == within[i] {

			j++
			i++
		}

		if j == inputLength {

			result = append(result, i-j)
			j = lps[j-1]
		} else if i < withinLength && input[j] != within[i] {

			if j != 0 {

				j = lps[j-1]
			} else {

				i++
			}
		}
	}

	return result
}

func generateGotoFunc(maxStates int) [][]int {

	numChars := 256 // ASCII-chars only.

	buffer := make([][]int, maxStates+1) // TODO: is this the right way around?

	for i := range buffer { // This should cycle through 256 times.

		buffer[i] = make([]int, numChars)

		for j := range buffer[i] {

			buffer[i][j] = -1
		}

		continue
	}

	return buffer
}

func generateOutFunc(maxStates int) []int {

	buffer := make([]int, maxStates)

	for i := range buffer {

		buffer[i] = 0
	}

	return buffer
}

func generateFailureFunc(maxStates int) []int {

	buffer := make([]int, maxStates)

	for i := range buffer {

		buffer[i] = -1
	}

	return buffer
}

func generateMatchingMachine(words []string, maxStates int) (int, []int, []int, [][]int) {

	//k := len(words)

	states := 1
	outFunc := generateOutFunc(maxStates)
	failureFunc := generateFailureFunc(maxStates)
	gotoFunc := generateGotoFunc(maxStates)

	for i, word := range words {

		currentState := 0

		for _, currentChar := range word {

			ord := currentChar

			if gotoFunc[currentState][ord] == -1 {

				gotoFunc[currentState][ord] = states
				states += 1
			}

			currentState = gotoFunc[currentState][ord]
		}

		outFunc[currentState] |= 1 << i
	}

	for i := 0; i < 256; i++ {

		if gotoFunc[0][i] == -1 {

			gotoFunc[0][i] = 0
		}
	}

	queue := make([]int, 0)

	for i := 0; i < 256; i++ {

		if gotoFunc[0][i] != 0 {

			failureFunc[gotoFunc[0][i]] = 0
			queue = append(queue, gotoFunc[0][i])
		}
	}

	for len(queue) > 0 {

		state := queue[0]
		queue = queue[1:]

		for i := 0; i < 256; i++ {

			if gotoFunc[state][i] != -1 {

				failure := failureFunc[state]

				for gotoFunc[failure][i] == -1 {

					failure = failureFunc[failure]
				}

				failure = gotoFunc[failure][i]

				failureFunc[gotoFunc[state][i]] = failure

				outFunc[gotoFunc[state][i]] |= outFunc[failure]

				queue = append(queue, gotoFunc[state][i])
			}
		}
	}

	return states, outFunc, failureFunc, gotoFunc
}

func findNextState(currentState int, nextInput rune, gotoFunc [][]int, failureFunc []int) int {

	answer := currentState

	for gotoFunc[answer][nextInput] == -1 {

		answer = failureFunc[answer]
	}

	return gotoFunc[answer][nextInput]
}

func performAhoCorasick(inputs []string, within string) []int {

	result := make([]int, 0)
	maxStates := 0

	for _, input := range inputs {

		maxStates = maxStates + len(input)
	}

	_, outFunc, failureFunc, gotoFunc := generateMatchingMachine(inputs, maxStates)

	fmt.Println(gotoFunc)
	fmt.Println("---------------------")
	fmt.Println(outFunc)
	fmt.Println("---------------------")
	fmt.Println(failureFunc)
	currentState := 0

	for i := 0; i < len(within); i++ {

		currentState := findNextState(currentState, rune(within[i]), gotoFunc, failureFunc)

		if outFunc[currentState] == 0 {

			continue
		}

		for j := 0; j < len(inputs); j++ {

			if outFunc[currentState]&(1<<j) > 0 {

				word := inputs[j]

				result = append(result, i-len(word)+1)
			}
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

func checkPacket(rules []Rule, packet gopacket.Packet, matchIndex int) bool {

	//fmt.Println(packet.String())

	for _, rule := range rules {

		//fmt.Println("Attempting to match rule: " + rule.encode())
		//fmt.Println("With packet: ---- " + packet.String())

		if rule.matchRule(packet) {

			fmt.Println("=================================================")
			fmt.Println("Match #" + fmt.Sprint(matchIndex) + ": matched rule: " + rule.encode())
			//fmt.Println("With packet: ---- " + packet.String())
			return true
		} else {

			//fmt.Println("Match failed")
		}

		//fmt.Println("")
		//fmt.Println("======================================================")
		//fmt.Println("")
	}

	return false
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

	matchIndex := 1

	for packet := range packetSource.Packets() {
		// Process packet here

		if checkPacket(rules, packet, matchIndex) {

			matchIndex = matchIndex + 1
		}
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

	/*content := "abc 123 ok go 123 aaaa bye"
	content2 := "abcaaadeaaaaf"
	find := []string{"aaa", "abc"}

	result1 := performBoyerMoore(find[0], content)
	result2 := performRabinKarp(find[0], content, 101)
	result3 := performKnuthMorrisPratt(find[0], content)
	result4 := performAhoCorasick(find, content2)

	fmt.Println(result1)
	fmt.Println(result2)
	fmt.Println(result3)
	fmt.Println(result4)*/

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
