# Web Application Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Maintenance](https://img.shields.io/badge/maintained%3F-yes-green.svg)](https://github.com/yourusername/crawler/graphs/commit-activity)

A powerful and feature-rich web application vulnerability scanner that helps identify SQL Injection and Cross-Site Scripting (XSS) vulnerabilities in web applications. This tool is designed for security professionals and developers to perform security assessments of their web applications.

##  Features

- **SQL Injection Detection**
  - Error-based SQLi detection
  - Time-based SQLi detection
  - Boolean/Union-based SQLi detection
  - Comprehensive payload testing

- **Cross-Site Scripting (XSS) Detection**
  - Reflected XSS testing
  - Multiple XSS payload testing
  - Parameter-based testing

- **Advanced Features**
  - Multi-threaded scanning
  - Tor proxy support with automatic rotation
  - Rate limiting and request throttling
  - Detailed HTML reports
  - Configurable scanning options
  - URL crawling with depth control
  - Error handling and retry mechanisms

##  Prerequisites

- Python 3.6 or higher
- Tor service (optional, for proxy support)
- Required Python packages (install via `pip install -r requirements.txt`)

##  Installation

1. Clone the repository:
```bash
git clone https://github.com/Otsmane-Ahmed/web-vuln-scanner.git
cd web-vuln-scanner
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. (Optional) Set up Tor service:
   - Install Tor on your system
   - Start the Tor service
   - The default Tor SOCKS proxy port is 9050

##  Configuration

The scanner uses a `config.json` file for configuration. You can modify the following settings:

```json
{
    "max_threads": 3,
    "max_retries": 3,
    "max_depth": 2,
    "timeout": 30,
    "delay_between_requests": 1,
    "verify_ssl": false,
    "rate_limit": {
        "requests_per_minute": 60,
        "burst_size": 10
    },
    "proxy": {
        "enabled": true,
        "tor_proxy": "socks5h://localhost:9050",
        "use_rotating_proxies": true
    },
    "scan_options": {
        "test_sqli": true,
        "test_xss": true,
        "test_path_traversal": false,
        "test_file_inclusion": false
    }
}
```

##  Usage

### Basic Usage

Scan a single URL:
```bash
python v5.py --url https://example.com
```

Scan URLs from a file:
```bash
python v5.py --file urls.txt
```

### Advanced Options

```bash
python v5.py --url https://example.com --depth 3 --threads 5 --no-tor --verify-ssl
```

Available options:
- `--url`: Target URL to scan
- `--file`: File containing URLs to scan
- `--depth`: Maximum crawl depth (default: 2)
- `--threads`: Number of concurrent threads
- `--no-tor`: Disable Tor proxy
- `--verify-ssl`: Enable SSL verification
- `--output-dir`: Directory for output files
- `--max-errors`: Maximum number of errors per URL before skipping

##  Output

The scanner generates:
1. HTML reports in the `reports/` directory
2. URL lists in the `urls/` directory
3. Log files in the `logs/` directory

##  Security Considerations

- Always obtain proper authorization before scanning any website
- Use responsibly and in accordance with applicable laws and regulations
- Be mindful of rate limits and server load
- Consider using Tor proxy for anonymous scanning
- Review and adjust configuration settings based on target environment

##  Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program.



##  Roadmap

- [ ] Add support for more vulnerability types
- [ ] Implement advanced crawling strategies
- [ ] Add API support for integration with other tools
- [ ] Improve reporting capabilities
- [ ] Add support for custom payloads
- [ ] Implement authentication handling
- [ ] Add support for different output formats

**Developed with ❤️ by Otsmane Ahmed**
