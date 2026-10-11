# SNAYZA-Phishing-Awareness

A Python terminal application for phishing awareness, defensive URL analysis, and cybersecurity education.

**Author:** Snayza  
**Version:** 1.0.0

## Features

- Static URL security analysis with heuristic risk scoring (0–100)
- Checks selected suspicious URL patterns
- Interactive phishing awareness quiz with explanations
- Cybersecurity awareness guide
- Safe educational URL examples
- Local JSON URL reports and quiz history
- Colored terminal interface
- Python standard library only
- No DNS lookups or network requests during analysis


  

  
## Screenshot

![SNAYZA Phishing Awareness](assets/Screenshot 2026-10-11 215050.png)


## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Git (for cloning)

No third-party Python packages are required.

## Installation

```bash
git clone https://github.com/Snayza/SNAYZA-Phishing-Awareness.git
cd SNAYZA-Phishing-Awareness
python main.py
```

If needed, use `python3 main.py` on Linux/macOS or `py main.py` on Windows.

## Menu

| Option | Description |
|---|---|
| 1 | Analyze a URL |
| 2 | Take the awareness quiz |
| 3 | Read the awareness guide |
| 4 | Review safe training examples |
| 5 | View saved URL reports |
| 0 | Exit |


## How the Analyzer Works

The analyzer checks selected characteristics such as HTTP usage, IP-based hostnames, user-information fields, Punycode labels, selected URL shorteners, long hostnames, subdomain count, and suspicious keywords.

The score is a heuristic indicator, not a probability that a URL is malicious.

## Limitations

- Does not query threat-intelligence databases.
- Does not perform DNS or network requests.
- Does not visit or crawl websites.
- May produce false positives and false negatives.
- HTTPS does not guarantee that a website is legitimate.
- A low score does not prove that a URL is safe.

## Ethical Use

SNAYZA-Phishing-Awareness is intended for cybersecurity education, defensive analysis, and awareness training. Analyze URLs responsibly. Never use this project to collect credentials, impersonate real services, or target other people.

## Author

**Snayza**

## License

This project is released under the MIT License. See `LICENSE` for details.
