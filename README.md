# Argus : A Dynamic Reconnaissance Tool For Shodan


Argus is a versatile reconnaissance tool designed for targeted information gathering using predefined dorks. Unlike traditional DNS enumerators, Argus goes beyond subdomain enumeration, retrieving both IP addresses and subdomains based on user-defined queries.

## Features

- **Dork-Based Approach:** Utilize predefined dorks to tailor reconnaissance queries for specific information.
- **IP and Subdomain Retrieval:** Retrieve comprehensive results by obtaining both IP addresses and subdomains.
- **Command-Line Interface:** User-friendly CLI for easy customization of dorks and query parameters.
- **Output Handling:** Save results to a file with support for managing unique entries and preventing duplicates.

# Installation

To install Argus, you can use the `go install` command. Make sure you have Go installed on your system.

```bash
go install github.com/ractiurd/argus@latest
```

## Usage

Argus streamlines the reconnaissance process by allowing users to define search criteria through dorks. Users can specify their Shodan API key, target domain, and additional options via command-line arguments, providing a straightforward and customizable experience.

### Example:

```bash
# Perform a reconnaissance search with a predefined dork
./argus -apikey <YOUR_SHODAN_API_KEY> -target example.com -c -s -o results.txt
```


### Command-Line Arguments

- **-api:** Your Shodan API key (required).
- **-org:** Organization name of the target.
- **-t:** Target domain for reconnaissance (required).
- **-c:** Choose a predefined dork.
- **-s:** Print only subdomains.
- **-i:** Print only IP addresses.
- **-o:** Save results to a file.

 # Dorks argus use
**SSL Certificate Subject Common Name and HTTP Status Code 200:**
   ```plaintext
   ssl.cert.subject.CN:"example.com" 200
```
**Hostname and HTTP Status Code 200:**
   ```plaintext
   shostname:"example.com" 200
```
**SSL Version and HTTP Status Code 200**
   ```plaintext
   ssl:"example.com" 200
```
**Organization Name and HTTP Status Code 200:**
   ```plaintext
   org:"YourOrg" 200
```
**ASN and HTTP Status Code 200:**
   ```plaintext
   asn:"AS12345" 200
```
# Conclusion

Argus represents a new era in reconnaissance, offering a powerful and flexible approach to information gathering. Whether you are a security professional conducting targeted assessments or a researcher exploring the expansive world of cybersecurity, Argus is designed to elevate your reconnaissance capabilities.

We welcome your feedback, contributions, and bug reports. Feel free to explore the source code, submit issues, or even contribute to the development of Argus. Together, we can make this tool even more robust and effective.

Thank you for choosing Argus. Happy reconnaissance!


## Author

- **Author:** Ractiurd
- **Twitter:** [@ractiurd](https://twitter.com/ractiurd)
