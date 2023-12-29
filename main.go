package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Predefined dorks
// Predefined dorks
// Predefined dorks
// Predefined dorks
// Predefined dorks
var predefinedDorks = []Dork{
	// the first part will bo shown in choice and the second part will be use on the querry

	{"ssl.cert.subject.CN:\"example.com\" 200", "ssl.cert.subject.CN:\"%s\"+200"},
	{"hostname:\"example.com\" 200", "hostname:\"%s\"+200"},
	{"ssl:\"example.com\" 200", "ssl:\"%s\"+200"},
	// Add more predefined dorks as needed
}

// Add more predefined dorks as needed
// Add more predefined dorks as needed
// Add more predefined dorks as needed
// Add more predefined dorks as needed
// Add more predefined dorks as needed

const (
	reset = "\033[0m"
	green = "\033[32m"
)

const shodanURL = "https://api.shodan.io/dns/domain/"
const shodanBaseURL = "https://api.shodan.io/shodan/host/search"

var uniqueMap = make(map[string]bool)

type ShodanResponse struct {
	Matches []struct {
		IPString string `json:"ip_str"`
	} `json:"matches"`
}

type SubdomainResponse struct {
	Domain     string      `json:"domain,omitempty"`
	Tags       []string    `json:"tags,omitempty"`
	Data       []Subdomain `json:"data,omitempty"`
	SubDomains []string    `json:"subdomains,omitempty"`
}

type Subdomain struct {
	SubD     string `json:"subdomain,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

type Dork struct {
	Description string
	Query       string
}

const argusLogo = `
    A     RRR      GGGG    U    U   SSSS
   / \    R   R   G        U    U  S
  / _ \   R ==R  G   GGG   U    U   SSS
 / ___ \  R R     G    G   U    U       S
/_/   \_\ R  RR     GGG      UU     SSSS

					Ractiurd

Twitter  : twitter.com/ractiurd
Facebook : facebook.com/Ractiurd
`

func main() {
	coloredLogo := fmt.Sprintf("%s", colorize(argusLogo, green))
	fmt.Println(coloredLogo)
	chooseDork, org, asn, apiKey, target, printSub, printIPs, output := parseCommandLineArguments()
	var dorkQuery string

	if asn != "" && org == "" && target == "" {
		err := asnipextracrt(apiKey, asn)
		if err != nil {
			log.Fatal(err)
		}
	}

	if asn == "" && org == "" && target != "" {
		if chooseDork {
			fmt.Println("Choose a predefined dork:")
			for i, dork := range predefinedDorks {
				fmt.Printf("%d. %s\n", i+1, dork.Description)
			}

			var choice int
			fmt.Print("Enter the number of the dork: ")
			_, err := fmt.Scan(&choice)
			if err != nil || choice < 1 || choice > len(predefinedDorks) {
				fmt.Println("Invalid choice. Using default dork.")
				dorkQuery = predefinedDorks[0].Query
			} else {
				dorkQuery = predefinedDorks[choice-1].Query
			}
		}

		if !chooseDork && dorkQuery == "" {

			defaultDorkQuery := fmt.Sprintf("ssl.cert.subject.CN:\"%s\" 200", target)
			matches := performShodanSearch(apiKey, defaultDorkQuery)
			subdomainRegex := regexp.MustCompile(fmt.Sprintf(`.*\.%s$`, regexp.QuoteMeta(target)))

			if printSub && printIPs {
				printResults(apiKey, target, matches, subdomainRegex, true, true)
			} else if printSub {
				printResults(apiKey, target, matches, subdomainRegex, true, false)
			} else if printIPs {
				printResults(apiKey, target, matches, subdomainRegex, false, true)
			} else {

				printResults(apiKey, target, matches, subdomainRegex, true, true)
			}
		} else {

			if strings.Contains(dorkQuery, "%s") {
				dorkQuery = fmt.Sprintf(dorkQuery, target)
			}

			matches := performShodanSearch(apiKey, dorkQuery)

			subdomainRegex := regexp.MustCompile(fmt.Sprintf(`.*\.%s$`, regexp.QuoteMeta(target)))

			if printSub && printIPs {
				printResults(apiKey, target, matches, subdomainRegex, true, true)
			} else if printSub {
				printResults(apiKey, target, matches, subdomainRegex, true, false)
			} else if printIPs {
				printResults(apiKey, target, matches, subdomainRegex, false, true)
			} else {

				printResults(apiKey, target, matches, subdomainRegex, true, true)
			}
		}
	}

	if org != "" && target == "" && asn == "" {
		err := GetOrganizationIPs(apiKey, org)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	}

	if output != "" {
		if _, err := os.Stat(output); os.IsNotExist(err) {

			file, err := os.Create(output)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			defer file.Close()

			for value := range uniqueMap {
				_, err := fmt.Fprintln(file, value)
				fmt.Println(value)
				if err != nil {
					fmt.Println("Error:", err)
					return
				}
			}
		} else {

			fileContent, err := ioutil.ReadFile(output)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			lines := strings.Split(string(fileContent), "\n")
			for _, line := range lines {
				uniqueMap[line] = true
			}

			file, err := os.Create(output)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			defer file.Close()

			for value := range uniqueMap {
				_, err := fmt.Fprintln(file, value)
				fmt.Println(value)
				if err != nil {
					fmt.Println("Error:", err)
					return
				}
			}
		}
	}

	if output == "" {
		for value := range uniqueMap {
			fmt.Println(value)
		}
	}
}

func parseCommandLineArguments() (bool, string, string, string, string, bool, bool, string) {
	apiKey := flag.String("api", "", "Shodan API Key")
	target := flag.String("t", "", "Target domain (e.g., target.com)")
	printSub := flag.Bool("s", false, "Print only subdomains")
	printIPs := flag.Bool("i", false, "Print only IP addresses")
	asn := flag.String("asn", "", "ASN number search")
	org := flag.String("org", "", "Org name must be put \"org\" ")
	chooseDork := flag.Bool("c", false, "Choose a predefined dork")
	output := flag.String("o", "", "save the result in given filename")
	flag.Parse()

	return *chooseDork, *org, *asn, *apiKey, *target, *printSub, *printIPs, *output
}

func performShodanSearch(apiKey, query string) []interface{} {
	apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, url.QueryEscape(query))
	response, err := http.Get(apiURL)
	if err != nil {
		log.Fatal("HTTP request error:", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal("Error reading response body:", err)
	}

	var rawResult json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	err = decoder.Decode(&rawResult)
	if err != nil {
		log.Fatal("Error decoding JSON:", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(rawResult, &result)
	if err != nil {
		log.Fatal("Error unmarshaling JSON:", err)
	}

	matches, ok := result["matches"].([]interface{})
	if !ok {
		log.Println("Warning: 'matches' is not an array. Attempting to handle this case.")
		if match, isNumber := result["matches"].(float64); isNumber {
			matches = []interface{}{match}
		} else {
			log.Fatal("Invalid 'matches' type in JSON response")
		}
	}

	return matches
}

func printResults(apiKey, target string, matches []interface{}, subdomainRegex *regexp.Regexp, printSub, printIP bool) {
	if printSub {
		printSubdomains(apiKey, target, matches, subdomainRegex)
		err := getSubdomains(apiKey, target)
		if err != nil {
			fmt.Println(err)
		}
		err1 := getSubdomainsjson(apiKey, target)
		if err1 != nil {
			fmt.Println(err1)
		}
	}

	if printIP {
		printIPAddresses(apiKey, matches)
	}
}

func printSubdomains(apiKey, target string, matches []interface{}, subdomainRegex *regexp.Regexp) {
	for _, match := range matches {
		hostnames, ok := match.(map[string]interface{})["hostnames"].([]interface{})
		if ok && len(hostnames) > 0 {
			subdomain := hostnames[0].(string)
			if subdomainRegex.MatchString(subdomain) {

				processAndPrintSubdomain(subdomain)
			}
		}
	}
}

func processAndPrintSubdomain(value string) {

	value = strings.TrimSpace(value)

	if _, exists := uniqueMap[value]; !exists {
		uniqueMap[value] = true
	}
}

func printIPAddresses(apiKey string, matches []interface{}) {
	for _, match := range matches {
		ipString, ok := match.(map[string]interface{})["ip_str"].(string)
		if ok {

			processAndPrintSubdomain(ipString)
		}
	}
}

func getSubdomains(apiKey, target string) error {
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s", target)

	response, err := http.Get(fmt.Sprintf("%s?key=%s", url, apiKey))
	if err != nil {
		return fmt.Errorf("Error making HTTP request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("Error reading response body: %v", err)
		}

		subdomainRegex := regexp.MustCompile(fmt.Sprintf(`"([^"]*\.%s)`, target))
		matches := subdomainRegex.FindAllStringSubmatch(string(body), -1)

		if len(matches) > 0 && len(matches[0]) == 2 {
			for _, match := range matches {
				sub := match[1]
				processAndPrintSubdomain(sub)
			}
		} else {
			fmt.Printf("No subdomains found for %s.\n", target)
		}
	} else {
		return fmt.Errorf("Error: %d", response.StatusCode)
	}

	return nil
}

func getSubdomainsjson(apiKey, target string) error {
	url := fmt.Sprintf("%s%s?key=%s", shodanURL, target, apiKey)

	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("Error making HTTP request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var subdomainResponse SubdomainResponse
		err := json.NewDecoder(response.Body).Decode(&subdomainResponse)
		if err != nil {
			return fmt.Errorf("Error decoding JSON response: %v", err)
		}

		if len(subdomainResponse.SubDomains) > 0 {
			for _, subdomain := range subdomainResponse.SubDomains {
				result := fmt.Sprintf("%s.%s\n", subdomain, target)
				processAndPrintSubdomain(result)

			}
		} else {
			fmt.Printf("No subdomains found for %s.\n", target)
		}
	} else {
		return fmt.Errorf("Error: %d", response.StatusCode)
	}

	return nil
}

func asnipextracrt(apiKey, asn string) error {
	dork := fmt.Sprintf("asn:\"%s\" 200", asn)
	url := fmt.Sprintf("%s?key=%s&query=%s", shodanBaseURL, apiKey, dork)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var shodanResp ShodanResponse
	err = json.Unmarshal(body, &shodanResp)
	if err != nil {
		return err
	}

	for _, match := range shodanResp.Matches {

		processAndPrintSubdomain(match.IPString)
	}

	return nil
}

func GetOrganizationIPs(apiKey, orgName string) error {

	url := fmt.Sprintf("%s?key=%s&query=org:\"%s\"", shodanBaseURL, apiKey, orgName)
	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error making Shodan API request: %v", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return fmt.Errorf("error decoding JSON: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Shodan API request failed: %v", result["error"])
	}

	for _, host := range result["matches"].([]interface{}) {
		ip := host.(map[string]interface{})["ip_str"].(string)
		formattedResult := fmt.Sprintf(ip)
		processAndPrintSubdomain(formattedResult)
	}

	return nil
}

func colorize(text, color string) string {
	return fmt.Sprintf("%s%s%s", color, text, reset)
}
