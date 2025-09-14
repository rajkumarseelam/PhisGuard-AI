#!/bin/bash

# Domain Crawler Setup Script
# ==========================

echo "🚀 Setting up Domain Crawler with Screenshot Capture"
echo "====================================================="

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    exit 1
fi

echo "✅ Python $python_version detected"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv crawler_env

# Activate virtual environment
source crawler_env/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Install Playwright browsers
echo "🌐 Installing Playwright browsers..."
playwright install chromium

# Check if Go is installed for external tools
if command -v go &> /dev/null; then
    echo "✅ Go detected, installing external subdomain tools..."
    
    # Install subfinder
    echo "📦 Installing subfinder..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    echo "✅ External tools installed"
else
    echo "⚠️  Go not found. External subdomain tools (subfinder, amass) won't be available."
    echo "   Install Go from https://golang.org/dl/ for enhanced subdomain discovery."
fi

# Create project structure
echo "📁 Creating project structure..."
mkdir -p {examples,config,results}

# Create sample configuration
cat > config/crawler_config.yaml << 'EOF'
crawler:
  max_concurrent: 10
  timeout: 30
  rate_limit: 5
  screenshot_full_page: true

subdomain_discovery:
  enable_dns_bruteforce: true
  enable_crt_search: true
  enable_external_tools: true

content_extraction:
  extract_text: true
  extract_html: true
  max_links: 100

output:
  base_directory: "crawl_results"
  save_json: true
  save_csv: true

logging:
  level: "INFO"
  log_to_file: true
EOF

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment: source crawler_env/bin/activate"
echo "2. Test the installation: python test_setup.py"
echo "3. Or crawl a domain: python crawler.py example.com"
echo ""
echo "Happy crawling! 🕷️"
