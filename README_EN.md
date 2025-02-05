# Directory Traversal Scanner 🔍

[English](README_EN.md) | [中文](README.md)

## 📖 Description

Directory Traversal Scanner is a high-performance security tool designed to detect and verify path traversal vulnerabilities in web applications. Leveraging asynchronous concurrent scanning and intelligent WAF bypass techniques, it helps security researchers quickly identify potential security risks.

## ✨ Features

- 🚄 Asynchronous concurrent scanning for large-scale target detection
- 🛡️ Built-in WAF bypass techniques
- 🎯 Intelligent parameter identification and target extraction
- 📊 Real-time scan progress display
- 📝 Automatic detailed scan report generation
- 🔄 Custom payload support
- 🌈 Beautiful command-line interface

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![aiohttp](https://img.shields.io/badge/aiohttp-latest-green)
![rich](https://img.shields.io/badge/rich-latest-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

- Python 3.8+
- aiohttp (Async HTTP Client/Server)
- rich (Terminal formatting)
- urllib.parse (URL parsing)

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/directory-traversal-scanner.git

# Navigate to project directory
cd directory-traversal-scanner

# Install dependencies
pip install -r requirements.txt
```

### 🎮 Basic Usage

```bash
# Scan a single URL
python scanner.py -u "http://example.com/page.php?file=test.txt"

# Scan multiple URLs with WAF bypass enabled
python scanner.py -u "http://example1.com" "http://example2.com" --waf

# Custom concurrency and timeout
python scanner.py -u "http://example.com" -c 200 -t 10
```

## 📋 Command Line Arguments

```
-u, --urls        Target URLs (Required, multiple supported)
-d, --depth       Maximum traversal depth (Default: 4)
--waf            Enable WAF bypass techniques
-c, --concurrency Maximum concurrent requests (Default: 20)
-t, --timeout     Request timeout in seconds (Default: 5)
-o, --output      Output report filename (Default: scan_report.json)
```

## 📊 Scan Reports

Detailed scan reports are generated in the `results` directory, including:
- Scan configuration
- Target URL list
- Scanning statistics
- Discovered vulnerability details
- Complete scan command

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only. Using this tool for unauthorized testing may violate applicable laws and regulations. Users must assume all risks and legal responsibilities.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## 🌟 Acknowledgments

- Thanks to all contributors
- Thanks to the open source community

---

💡 **Tip**: If you find this project helpful, please give it a Star!
