package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Source: https://docs.suricata.io/en/latest/rules/intro.html

func parseOptions(raw string) RuleOptions {

	options := RuleOptions{options: make(map[string]string)}

	parts := strings.Split(raw[1:len(raw)-1], ";")

	for _, part := range parts {

		// Skip empty parts.

		if len(part) == 0 {

			continue
		}

		keyPair := strings.SplitN(part, ":", 2)

		// Skip empty keypairs.

		if len(keyPair) == 1 {

			options.options[strings.TrimSpace(keyPair[0])] = ""
		} else {

			options.options[strings.TrimSpace(keyPair[0])] = strings.TrimSpace(keyPair[1])
		}
	}

	return options
}

func parsePort(portString string) int {

	port := -1

	if portString != "any" {

		temp, err := strconv.Atoi(portString)

		if err != nil {

			fmt.Println("Invalid port: " + portString)
			os.Exit(4)
		}

		port = temp
	}

	return port
}

func parseLine(line string) Rule {

	// There will be 7 spaces before getting to the rule options.

	parts := strings.SplitN(line, " ", 8)

	if len(parts) < 7 {

		fmt.Println("Line had too few spaces to be a valid rule.")
		os.Exit(3)
	}

	// Index 0 is the action.

	action := RuleAction{actionType: Action(parts[0])}

	// Index 1 = protocol
	// Index 2 = source
	// Index 3 = source port
	// Index 4 = direction
	// Index 5 = destination
	// Index 6 = destination port

	header := RuleHeader{
		protocol:        Protocol(parts[1]),
		direction:       Direction(parts[4]),
		source:          parts[2],
		sourcePort:      parsePort(parts[3]),
		destination:     parts[5],
		destinationPort: parsePort(parts[6]),
	}

	// Everything at index 7 and beyond are the options.

	options := parseOptions(parts[7])

	return Rule{
		action:  action,
		header:  header,
		options: options,
	}
}

func parseSuricataRules(fileName string) []Rule {

	rules := make([]Rule, 0)

	// Open the file of rules.

	file, err := os.Open(fileName)

	if err != nil {

		fmt.Println("Error opening file: " + err.Error())
		os.Exit(1)
	}

	// Cycle through each line of the file.

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := scanner.Text()

		// Skip lines that are empty or commented out.

		if len(line) == 0 || line[0] == '#' {

			continue
		}

		// Parse the line as a rule and append it to the list of rules.

		rules = append(rules, parseLine(line))
	}

	// Close the file.

	err = file.Close()

	if err != nil {
		fmt.Println("Error closing file: " + err.Error())
		os.Exit(2)
	}

	// Return the completed list of rules.

	return rules
}
