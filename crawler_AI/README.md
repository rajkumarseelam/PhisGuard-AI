# Domain Crawler with Screenshot Capture

A comprehensive domain crawler that discovers subdomains, extracts content, and captures screenshots.

## Features

- 🔍 **Multi-method subdomain discovery** (DNS, certificate transparency, external tools)
- 🌐 **Modern browser automation** with Playwright
- 📸 **Full-page screenshot capture**
- 📄 **Complete text extraction** and content analysis
- ⚡ **Concurrent processing** for speed
- 📊 **Comprehensive reporting** and analysis
- 🛡️ **Security insights** and technology detection

## Quick Start

1. **Setup**:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   source crawler_env/bin/activate
   ```

2. **Test installation**:
   ```bash
   python test_setup.py
   ```

3. **Run quick example**:
   ```bash
   python quick_start.py
   ```

4. **Crawl a domain**:
   ```bash
   python crawler.py example.com
   ```

## Usage Examples

- **Simple crawl**: `python crawler.py example.com --skip-subdomains`
- **Full crawl**: `python crawler.py example.com -o results/example_crawl`
- **High concurrency**: `python crawler.py example.com -c 20 -t 45`
- **Analyze results**: `python analyzer.py results/*/data/crawl_results_*.json`

## Output Structure

```
crawl_results/
├── screenshots/          # Page screenshots (PNG)
├── content/              # Text and HTML content
├── data/                 # JSON results and CSV summaries
└── crawler.log           # Crawl log
```

## Configuration

Create custom configuration:
```bash
python crawler_config.py create-config
# Edit crawler_config.yaml
```

## Requirements

- Python 3.8+
- Playwright (automatically installed)
- Optional: Go (for external subdomain tools)

See `requirements.txt` for full dependencies.

## License

Apache License 2.0 - See LICENSE file for details.
