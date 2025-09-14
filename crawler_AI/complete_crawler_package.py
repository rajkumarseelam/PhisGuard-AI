#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Complete Domain Crawler Package Extractor
=========================================

This script contains all the files for the Domain Crawler project.
Run it to extract all files to the current directory.

Usage: python extract_crawler_files.py

After extraction, run: ./setup.sh
"""

import os
import stat
from pathlib import Path

def create_file(filepath, content, executable=False):
    """Create a file with the given content"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    if executable:
        # Make file executable
        st = os.stat(filepath)
        os.chmod(filepath, st.st_mode | stat.S_IEXEC)
    
    print(f"Created: {filepath}")

def extract_all_files():
    """Extract all crawler files to current directory"""
    
    print("🚀 Extracting Domain Crawler Package...")
    print("=" * 50)
    
    # Main crawler file
    crawler_py = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__|

Domain Crawler with Screenshot Capture
======================================

A comprehensive domain crawler that:
- Discovers subdomains using multiple methods
- Crawls all discovered domains/subdomains
- Extracts text content from web pages
- Captures screenshots of each page
- Handles JavaScript-heavy sites
- Provides concurrent processing for speed

Dependencies:
pip install playwright beautifulsoup4 aiohttp aiofiles dnspython requests tldextract asyncio-throttle

playwright install chromium
"""

import asyncio
import aiohttp
import aiofiles
import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse, quote
from typing import Set, List, Dict, Optional, Tuple
import logging
import argparse
import time
import hashlib

# Third-party imports
try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    from bs4 import BeautifulSoup
    import dns.resolver
    import tldextract
    import requests
    from asyncio_throttle import Throttler
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install playwright beautifulsoup4 aiohttp aiofiles dnspython requests tldextract asyncio-throttle")
    print("Then run: playwright install chromium")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('crawler.log')
    ]
)
logger = logging.getLogger(__name__)

class SubdomainDiscovery:
    """Handles subdomain discovery using multiple methods"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = set()
        
    async def discover_subdomains(self) -> Set[str]:
        """Main method to discover subdomains using multiple techniques"""
        logger.info(f"Starting subdomain discovery for {self.domain}")
        
        # Method 1: DNS bruteforce with common subdomains
        await self._dns_bruteforce()
        
        # Method 2: Certificate transparency logs
        await self._crt_sh_search()
        
        # Method 3: External tools (if available)
        await self._external_tools()
        
        # Method 4: DNS zone transfer attempt
        await self._zone_transfer()
        
        # Add the main domain
        self.subdomains.add(self.domain)
        
        logger.info(f"Found {len(self.subdomains)} subdomains for {self.domain}")
        return self.subdomains
    
    async def _dns_bruteforce(self):
        """Bruteforce common subdomain names"""
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'test', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
            'vpn', 'ns', 'dns', 'search', 'api', 'exchange', 'git', 'upload', 'stage',
            'demo', 'app', 'mobile', 'm', 'shop', 'store', 'support', 'help', 'docs',
            'cdn', 'media', 'static', 'assets', 'img', 'images', 'video', 'auth',
            'login', 'secure', 'ssl', 'tcp', 'db', 'database', 'mysql', 'sql',
            'beta', 'alpha', 'staging', 'production', 'prod', 'live'
        ]
        
        tasks = []
        for sub in common_subs:
            subdomain = f"{sub}.{self.domain}"
            tasks.append(self._check_subdomain(subdomain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str):
                self.subdomains.add(result)
    
    async def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if a subdomain exists via DNS lookup"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try A record
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: resolver.resolve(subdomain, 'A')
                )
                return subdomain
            except:
                pass
            
            # Try AAAA record
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: resolver.resolve(subdomain, 'AAAA')
                )
                return subdomain
            except:
                pass
                
        except Exception as e:
            pass
        return None
    
    async def _crt_sh_search(self):
        """Search certificate transparency logs via crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            common_name = entry.get('common_name', '')
                            if common_name and common_name.endswith(self.domain):
                                # Clean up wildcard certificates
                                if common_name.startswith('*.'):
                                    common_name = common_name[2:]
                                self.subdomains.add(common_name)
                            
                            # Check SAN entries
                            name_value = entry.get('name_value', '')
                            if name_value:
                                for name in name_value.split('\\n'):
                                    name = name.strip()
                                    if name.endswith(self.domain):
                                        if name.startswith('*.'):
                                            name = name[2:]
                                        self.subdomains.add(name)
        except Exception as e:
            logger.warning(f"Certificate transparency search failed: {e}")
    
    async def _external_tools(self):
        """Use external tools if available (subfinder, amass, etc.)"""
        tools = ['subfinder', 'amass']
        
        for tool in tools:
            try:
                if tool == 'subfinder':
                    cmd = ['subfinder', '-d', self.domain, '-silent']
                elif tool == 'amass':
                    cmd = ['amass', 'enum', '-passive', '-d', self.domain]
                else:
                    continue
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                if process.returncode == 0:
                    subdomains = stdout.decode().strip().split('\\n')
                    for sub in subdomains:
                        sub = sub.strip()
                        if sub and sub.endswith(self.domain):
                            self.subdomains.add(sub)
                    logger.info(f"Found {len(subdomains)} subdomains using {tool}")
                    
            except FileNotFoundError:
                logger.debug(f"{tool} not found, skipping")
            except Exception as e:
                logger.warning(f"Error running {tool}: {e}")
    
    async def _zone_transfer(self):
        """Attempt DNS zone transfer (rarely works but worth trying)"""
        try:
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(self.domain, 'NS')
            
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.domain))
                    for name, node in zone.nodes.items():
                        if name != '@':
                            subdomain = f"{name}.{self.domain}"
                            self.subdomains.add(subdomain)
                except Exception:
                    continue
        except Exception:
            pass

class WebCrawler:
    """Main web crawler class that handles page crawling and data extraction"""
    
    def __init__(self, output_dir: str = "crawl_results", max_concurrent: int = 10, 
                 timeout: int = 30, user_agent: str = None):
        self.output_dir = Path(output_dir)
        self.screenshots_dir = self.output_dir / "screenshots"
        self.content_dir = self.output_dir / "content"
        self.data_dir = self.output_dir / "data"
        
        # Create directories
        for dir_path in [self.output_dir, self.screenshots_dir, self.content_dir, self.data_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        
        # Results storage
        self.results = []
        self.failed_urls = []
        
        # Rate limiting
        self.throttler = Throttler(rate_limit=5)  # 5 requests per second
    
    async def crawl_domains(self, domains: Set[str]) -> List[Dict]:
        """Main method to crawl all domains"""
        logger.info(f"Starting to crawl {len(domains)} domains")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding',
                ]
            )
            
            try:
                # Create semaphore for concurrent control
                semaphore = asyncio.Semaphore(self.max_concurrent)
                
                # Create crawling tasks
                tasks = []
                for domain in domains:
                    for scheme in ['https', 'http']:
                        url = f"{scheme}://{domain}"
                        tasks.append(self._crawl_single_url(browser, semaphore, url))
                
                # Execute all tasks
                await asyncio.gather(*tasks, return_exceptions=True)
                
            finally:
                await browser.close()
        
        # Save results
        await self._save_results()
        
        logger.info(f"Crawling completed. Processed {len(self.results)} pages, "
                   f"failed on {len(self.failed_urls)} URLs")
        
        return self.results
    
    async def _crawl_single_url(self, browser: Browser, semaphore: asyncio.Semaphore, url: str):
        """Crawl a single URL with concurrency control"""
        async with semaphore:
            async with self.throttler:
                try:
                    context = await browser.new_context(
                        user_agent=self.user_agent,
                        viewport={'width': 1366, 'height': 768},
                        ignore_https_errors=True
                    )
                    
                    page = await context.new_page()
                    
                    try:
                        # Navigate to page with timeout
                        response = await page.goto(
                            url, 
                            timeout=self.timeout * 1000,
                            wait_until='domcontentloaded'
                        )
                        
                        if not response or response.status >= 400:
                            raise Exception(f"HTTP {response.status if response else 'No response'}")
                        
                        # Wait for page to load
                        await page.wait_for_timeout(2000)
                        
                        # Extract data
                        result = await self._extract_page_data(page, url)
                        
                        if result:
                            self.results.append(result)
                            logger.info(f"Successfully crawled: {url}")
                        
                    except Exception as e:
                        self.failed_urls.append({"url": url, "error": str(e)})
                        logger.warning(f"Failed to crawl {url}: {e}")
                    
                    finally:
                        await context.close()
                        
                except Exception as e:
                    self.failed_urls.append({"url": url, "error": str(e)})
                    logger.error(f"Browser error for {url}: {e}")
    
    async def _extract_page_data(self, page: Page, url: str) -> Optional[Dict]:
        """Extract all relevant data from a page"""
        try:
            # Get basic page info
            title = await page.title()
            final_url = page.url
            
            # Get page content
            content = await page.content()
            
            # Extract text using BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text content
            text_content = soup.get_text()
            # Clean up whitespace
            lines = (line.strip() for line in text_content.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text_content = ' '.join(chunk for chunk in chunks if chunk)
            
            # Extract metadata
            meta_description = ""
            meta_keywords = ""
            
            description_tag = soup.find("meta", attrs={"name": "description"})
            if description_tag:
                meta_description = description_tag.get("content", "")
            
            keywords_tag = soup.find("meta", attrs={"name": "keywords"})
            if keywords_tag:
                meta_keywords = keywords_tag.get("content", "")
            
            # Extract headers
            headers = {}
            for i in range(1, 7):
                header_tags = soup.find_all(f'h{i}')
                headers[f'h{i}'] = [tag.get_text().strip() for tag in header_tags]
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                text = link.get_text().strip()
                if href:
                    absolute_url = urljoin(final_url, href)
                    links.append({"url": absolute_url, "text": text})
            
            # Extract images
            images = []
            for img in soup.find_all('img', src=True):
                src = img['src']
                alt = img.get('alt', '')
                if src:
                    absolute_url = urljoin(final_url, src)
                    images.append({"url": absolute_url, "alt": alt})
            
            # Take screenshot
            screenshot_filename = self._generate_filename(final_url, "png")
            screenshot_path = self.screenshots_dir / screenshot_filename
            
            await page.screenshot(
                path=str(screenshot_path),
                full_page=True,
                type='png'
            )
            
            # Save text content to file
            content_filename = self._generate_filename(final_url, "txt")
            content_path = self.content_dir / content_filename
            
            async with aiofiles.open(content_path, 'w', encoding='utf-8') as f:
                await f.write(text_content)
            
            # Save raw HTML
            html_filename = self._generate_filename(final_url, "html")
            html_path = self.content_dir / html_filename
            
            async with aiofiles.open(html_path, 'w', encoding='utf-8') as f:
                await f.write(content)
            
            # Create result object
            result = {
                "url": final_url,
                "original_url": url,
                "title": title,
                "status_code": 200,  # If we got here, it was successful
                "meta_description": meta_description,
                "meta_keywords": meta_keywords,
                "headers": headers,
                "links_count": len(links),
                "images_count": len(images),
                "text_length": len(text_content),
                "word_count": len(text_content.split()),
                "screenshot_path": str(screenshot_path),
                "content_path": str(content_path),
                "html_path": str(html_path),
                "crawl_timestamp": datetime.now().isoformat(),
                "links": links[:50],  # Limit to first 50 links
                "images": images[:50],  # Limit to first 50 images
                "domain": urlparse(final_url).netloc,
                "path": urlparse(final_url).path,
                "text_preview": text_content[:500] if text_content else ""
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error extracting data from {url}: {e}")
            return None
    
    def _generate_filename(self, url: str, extension: str) -> str:
        """Generate a safe filename from URL"""
        # Parse URL
        parsed = urlparse(url)
        
        # Create base name from domain and path
        domain = parsed.netloc.replace('www.', '')
        path = parsed.path.strip('/').replace('/', '_')
        
        if path:
            base_name = f"{domain}_{path}"
        else:
            base_name = domain
        
        # Clean filename
        base_name = re.sub(r'[<>:"/\\\\|?*]', '_', base_name)
        base_name = base_name[:100]  # Limit length
        
        # Add hash to ensure uniqueness
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        
        return f"{base_name}_{url_hash}.{extension}"
    
    async def _save_results(self):
        """Save crawl results to JSON file"""
        results_file = self.data_dir / f"crawl_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Prepare summary data
        summary = {
            "crawl_timestamp": datetime.now().isoformat(),
            "total_attempted": len(self.results) + len(self.failed_urls),
            "successful": len(self.results),
            "failed": len(self.failed_urls),
            "results": self.results,
            "failed_urls": self.failed_urls
        }
        
        async with aiofiles.open(results_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(summary, indent=2, ensure_ascii=False))
        
        logger.info(f"Results saved to {results_file}")
        
        # Save CSV summary
        csv_file = self.data_dir / f"crawl_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        csv_content = "URL,Title,Status,Text Length,Links Count,Images Count,Screenshot Path\\n"
        for result in self.results:
            csv_content += f"\\"{result['url']}\\",\\"{result['title']}\\",200,{result['text_length']},{result['links_count']},{result['images_count']},\\"{result['screenshot_path']}\\"\\n"
        
        async with aiofiles.open(csv_file, 'w', encoding='utf-8') as f:
            await f.write(csv_content)
        
        logger.info(f"CSV summary saved to {csv_file}")

async def main():
    """Main function to run the domain crawler"""
    parser = argparse.ArgumentParser(description="Domain Crawler with Screenshot Capture")
    parser.add_argument("domain", help="Target domain to crawl")
    parser.add_argument("-o", "--output", default="crawl_results", help="Output directory")
    parser.add_argument("-c", "--concurrent", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Page load timeout in seconds")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain discovery")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Extract domain from URL if provided
    if args.domain.startswith(('http://', 'https://')):
        parsed = urlparse(args.domain)
        domain = parsed.netloc
    else:
        domain = args.domain
    
    logger.info(f"Starting domain crawl for: {domain}")
    
    # Discover subdomains
    domains_to_crawl = set()
    
    if args.skip_subdomains:
        domains_to_crawl.add(domain)
    else:
        subdomain_discovery = SubdomainDiscovery(domain)
        domains_to_crawl = await subdomain_discovery.discover_subdomains()
    
    logger.info(f"Found {len(domains_to_crawl)} domains to crawl")
    
    # Initialize crawler
    crawler = WebCrawler(
        output_dir=args.output,
        max_concurrent=args.concurrent,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    # Start crawling
    start_time = time.time()
    results = await crawler.crawl_domains(domains_to_crawl)
    end_time = time.time()
    
    # Print summary
    print(f"\\n{'='*50}")
    print(f"CRAWL SUMMARY")
    print(f"{'='*50}")
    print(f"Target Domain: {domain}")
    print(f"Total Domains: {len(domains_to_crawl)}")
    print(f"Successful Pages: {len(results)}")
    print(f"Failed URLs: {len(crawler.failed_urls)}")
    print(f"Total Time: {end_time - start_time:.2f} seconds")
    print(f"Output Directory: {crawler.output_dir}")
    print(f"{'='*50}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Crawl interrupted by user")
    except Exception as e:
        logger.error(f"Crawl failed: {e}")
        sys.exit(1)
'''
    
    # Requirements file
    requirements_txt = '''# Requirements for Domain Crawler
# Install with: pip install -r requirements.txt

# Core dependencies
playwright>=1.40.0
beautifulsoup4>=4.12.0
aiohttp>=3.9.0
aiofiles>=23.0.0
dnspython>=2.4.0
requests>=2.31.0
tldextract>=5.0.0
asyncio-throttle>=1.0.2

# Optional but recommended external tools
# Install separately:
# - subfinder: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# - amass: go install github.com/owasp-amass/amass/v4/...@master

# Data processing and analysis
pandas>=2.0.0
numpy>=1.24.0

# Additional utilities
colorlog>=6.7.0
tqdm>=4.65.0
pyyaml>=6.0

# Development dependencies (optional)
pytest>=7.4.0
black>=23.0.0
flake8>=6.0.0

# After installation, run:
# playwright install chromium'''

    # Configuration file
    crawler_config_py = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Domain Crawler Configuration and Usage Examples
===============================================

This file provides configuration options and usage examples for the domain crawler.
"""

import yaml
from pathlib import Path
from typing import Dict, List, Any

# Default configuration
DEFAULT_CONFIG = {
    "crawler": {
        "max_concurrent": 10,
        "timeout": 30,
        "rate_limit": 5,  # requests per second
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "follow_redirects": True,
        "verify_ssl": False,
        "screenshot_full_page": True,
        "screenshot_format": "png",  # png or jpeg
        "max_retries": 3,
        "retry_delay": 2  # seconds
    },
    "subdomain_discovery": {
        "enable_dns_bruteforce": True,
        "enable_crt_search": True,
        "enable_external_tools": True,
        "enable_zone_transfer": True,
        "dns_timeout": 2,
        "custom_wordlist": None,  # path to custom subdomain wordlist
        "external_tools": ["subfinder", "amass"],
        "max_depth": 3  # subdomain depth (e.g., test.api.example.com = depth 2)
    },
    "content_extraction": {
        "extract_text": True,
        "extract_html": True,
        "extract_links": True,
        "extract_images": True,
        "extract_metadata": True,
        "extract_headers": True,
        "min_text_length": 100,  # minimum text length to save
        "max_links": 100,  # maximum number of links to save per page
        "max_images": 50   # maximum number of images to save per page
    },
    "output": {
        "base_directory": "crawl_results",
        "create_subdirs": True,
        "save_json": True,
        "save_csv": True,
        "save_html": True,
        "compress_results": False,
        "timestamp_format": "%Y%m%d_%H%M%S"
    },
    "filtering": {
        "skip_file_extensions": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar", ".exe"],
        "skip_content_types": ["application/pdf", "application/octet-stream"],
        "min_response_size": 100,  # bytes
        "max_response_size": 50000000,  # 50MB
        "skip_404": True,
        "skip_redirects_outside_domain": True
    },
    "logging": {
        "level": "INFO",  # DEBUG, INFO, WARNING, ERROR, CRITICAL
        "log_to_file": True,
        "log_filename": "crawler.log",
        "max_log_size": "10MB",
        "backup_count": 5
    }
}

class CrawlerConfig:
    """Configuration manager for the domain crawler"""
    
    def __init__(self, config_file: str = None):
        self.config = DEFAULT_CONFIG.copy()
        if config_file and Path(config_file).exists():
            self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                self._merge_config(self.config, user_config)
        except Exception as e:
            print(f"Error loading config file {config_file}: {e}")
    
    def _merge_config(self, default: Dict, user: Dict):
        """Recursively merge user configuration with default"""
        for key, value in user.items():
            if key in default:
                if isinstance(value, dict) and isinstance(default[key], dict):
                    self._merge_config(default[key], value)
                else:
                    default[key] = value
            else:
                default[key] = value
    
    def get(self, section: str, key: str = None):
        """Get configuration value"""
        if key is None:
            return self.config.get(section, {})
        return self.config.get(section, {}).get(key)
    
    def save_config(self, filename: str):
        """Save current configuration to file"""
        with open(filename, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2)

def create_sample_config(filename: str = "crawler_config.yaml"):
    """Create a sample configuration file"""
    with open(filename, 'w') as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, indent=2)
    print(f"Sample configuration created: {filename}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "create-config":
        create_sample_config()
'''

    # Analyzer file
    analyzer_py = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Crawl Results Analyzer
=====================

This script provides comprehensive analysis of domain crawl results,
including statistics, visualizations, and security insights.
"""

import json
import csv
import argparse
import sys
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict, Any
from datetime import datetime
import re
from urllib.parse import urlparse

# Optional imports for enhanced analysis
try:
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    from wordcloud import WordCloud
    import networkx as nx
    HAS_ANALYSIS_LIBS = True
except ImportError:
    HAS_ANALYSIS_LIBS = False
    print("Warning: Advanced analysis libraries not available. Install with:")
    print("pip install pandas matplotlib seaborn wordcloud networkx")

class CrawlAnalyzer:
    """Analyzer for domain crawl results"""
    
    def __init__(self, results_file: str):
        self.results_file = Path(results_file)
        self.data = self._load_data()
        self.results = self.data.get('results', [])
        self.failed_urls = self.data.get('failed_urls', [])
        
    def _load_data(self) -> Dict:
        """Load crawl results from JSON file"""
        try:
            with open(self.results_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading results file: {e}")
            sys.exit(1)
    
    def generate_report(self, output_dir: str = None) -> str:
        """Generate comprehensive analysis report"""
        if output_dir is None:
            output_dir = self.results_file.parent / "analysis"
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        report = []
        report.append("# Domain Crawl Analysis Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Results file: {self.results_file}")
        report.append("=" * 50)
        report.append("")
        
        # Basic statistics
        report.extend(self._basic_statistics())
        report.append("")
        
        # Domain analysis
        report.extend(self._domain_analysis())
        report.append("")
        
        # Content analysis
        report.extend(self._content_analysis())
        report.append("")
        
        # Technology detection
        report.extend(self._technology_detection())
        report.append("")
        
        # Security insights
        report.extend(self._security_analysis())
        report.append("")
        
        # Failed URLs analysis
        report.extend(self._failed_urls_analysis())
        
        # Save report
        report_text = "\\n".join(report)
        report_file = output_path / f"crawl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"Analysis report saved to: {report_file}")
        
        # Generate additional outputs
        if HAS_ANALYSIS_LIBS:
            self._generate_visualizations(output_path)
            self._export_detailed_data(output_path)
        
        return str(report_file)
    
    def _basic_statistics(self) -> List[str]:
        """Generate basic crawl statistics"""
        stats = []
        stats.append("## Basic Statistics")
        stats.append("-" * 20)
        
        total_attempted = self.data.get('total_attempted', len(self.results) + len(self.failed_urls))
        successful = len(self.results)
        failed = len(self.failed_urls)
        
        stats.append(f"Total URLs attempted: {total_attempted}")
        stats.append(f"Successful crawls: {successful} ({successful/total_attempted*100:.1f}%)")
        stats.append(f"Failed crawls: {failed} ({failed/total_attempted*100:.1f}%)")
        stats.append("")
        
        if self.results:
            # Content statistics
            text_lengths = [r.get('text_length', 0) for r in self.results]
            word_counts = [r.get('word_count', 0) for r in self.results]
            link_counts = [r.get('links_count', 0) for r in self.results]
            image_counts = [r.get('images_count', 0) for r in self.results]
            
            stats.append(f"Average text length: {sum(text_lengths)/len(text_lengths):.0f} characters")
            stats.append(f"Average word count: {sum(word_counts)/len(word_counts):.0f} words")
            stats.append(f"Average links per page: {sum(link_counts)/len(link_counts):.1f}")
            stats.append(f"Average images per page: {sum(image_counts)/len(image_counts):.1f}")
            stats.append("")
            
            # Top pages by content
            top_content = sorted(self.results, key=lambda x: x.get('text_length', 0), reverse=True)[:5]
            stats.append("Top 5 pages by content length:")
            for i, page in enumerate(top_content, 1):
                stats.append(f"  {i}. {page.get('title', 'No title')[:50]}... "
                           f"({page.get('text_length', 0)} chars)")
        
        return stats
    
    def _domain_analysis(self) -> List[str]:
        """Analyze domains and subdomains found"""
        analysis = []
        analysis.append("## Domain Analysis")
        analysis.append("-" * 18)
        
        domains = [r.get('domain', '') for r in self.results]
        domain_counter = Counter(domains)
        
        analysis.append(f"Total unique domains: {len(domain_counter)}")
        analysis.append("")
        
        # Top domains by page count
        analysis.append("Top domains by page count:")
        for domain, count in domain_counter.most_common(10):
            analysis.append(f"  {domain}: {count} pages")
        analysis.append("")
        
        return analysis
    
    def _content_analysis(self) -> List[str]:
        """Analyze page content patterns"""
        analysis = []
        analysis.append("## Content Analysis")
        analysis.append("-" * 18)
        
        # Title analysis
        titles = [r.get('title', '') for r in self.results if r.get('title')]
        title_words = []
        for title in titles:
            title_words.extend(title.lower().split())
        
        if title_words:
            common_title_words = Counter(title_words).most_common(10)
            analysis.append("Most common words in page titles:")
            for word, count in common_title_words:
                if len(word) > 3:  # Skip short words
                    analysis.append(f"  {word}: {count}")
        
        return analysis
    
    def _technology_detection(self) -> List[str]:
        """Detect technologies used on crawled sites"""
        analysis = []
        analysis.append("## Technology Detection")
        analysis.append("-" * 22)
        
        tech_indicators = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-admin'],
            'Drupal': ['/sites/default/', '/modules/', '/themes/'],
            'React': ['react', '_react'],
            'PHP': ['.php'],
            'API': ['/api/', '/rest/', '/graphql']
        }
        
        tech_counts = defaultdict(int)
        
        for result in self.results:
            url = result.get('url', '').lower()
            title = result.get('title', '').lower()
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator in url or indicator in title:
                        tech_counts[tech] += 1
                        break
        
        if tech_counts:
            analysis.append("Technologies detected:")
            for tech, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(self.results)) * 100
                analysis.append(f"  {tech}: {count} pages ({percentage:.1f}%)")
        
        return analysis
    
    def _security_analysis(self) -> List[str]:
        """Analyze security-related aspects"""
        analysis = []
        analysis.append("## Security Analysis")
        analysis.append("-" * 19)
        
        https_count = sum(1 for r in self.results if r.get('url', '').startswith('https://'))
        http_count = sum(1 for r in self.results if r.get('url', '').startswith('http://'))
        
        total_pages = len(self.results)
        if total_pages > 0:
            analysis.append(f"HTTPS usage: {https_count} pages ({https_count/total_pages*100:.1f}%)")
            analysis.append(f"HTTP usage: {http_count} pages ({http_count/total_pages*100:.1f}%)")
        
        return analysis
    
    def _failed_urls_analysis(self) -> List[str]:
        """Analyze failed URLs and common error patterns"""
        analysis = []
        analysis.append("## Failed URLs Analysis")
        analysis.append("-" * 22)
        
        if not self.failed_urls:
            analysis.append("No failed URLs recorded.")
            return analysis
        
        analysis.append(f"Total failed URLs: {len(self.failed_urls)}")
        
        return analysis
    
    def _generate_visualizations(self, output_dir: Path):
        """Generate visualizations using matplotlib/seaborn"""
        pass  # Placeholder
    
    def _export_detailed_data(self, output_dir: Path):
        """Export detailed data for further analysis"""
        pass  # Placeholder

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Analyze domain crawl results")
    parser.add_argument("results_file", help="Path to the crawl results JSON file")
    parser.add_argument("-o", "--output", help="Output directory for analysis results")
    
    args = parser.parse_args()
    
    if not Path(args.results_file).exists():
        print(f"Error: Results file {args.results_file} not found")
        sys.exit(1)
    
    analyzer = CrawlAnalyzer(args.results_file)
    report_file = analyzer.generate_report(args.output)
    
    print(f"\\nAnalysis completed. Report saved to: {report_file}")

if __name__ == "__main__":
    main()
'''

    # Setup script
    setup_sh = '''#!/bin/bash

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
'''

    # Test script
    test_setup_py = '''#!/usr/bin/env python3
"""Test script to verify installation"""

def test_imports():
    """Test if all required modules can be imported"""
    try:
        import asyncio
        import aiohttp
        import playwright
        from bs4 import BeautifulSoup
        import dns.resolver
        print("✅ All core dependencies imported successfully")
        
        # Test Playwright
        from playwright.async_api import async_playwright
        print("✅ Playwright imported successfully")
        
        # Test optional dependencies
        try:
            import pandas as pd
            import matplotlib.pyplot as plt
            print("✅ Analysis libraries available")
        except ImportError:
            print("⚠️  Analysis libraries not available (optional)")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Domain Crawler installation...")
    if test_imports():
        print("\\n🎉 Installation test successful!")
        print("   Run 'python crawler.py example.com --skip-subdomains' to try the crawler")
    else:
        print("\\n❌ Installation test failed!")
        print("   Please check the installation steps")
'''

    # Quick start example
    quick_start_py = '''#!/usr/bin/env python3
"""
Quick Start Example for Domain Crawler
======================================
"""

import asyncio
import sys
from pathlib import Path

# Import crawler modules (assuming they're in the same directory)
try:
    from crawler import WebCrawler, SubdomainDiscovery
except ImportError:
    print("Error: Make sure crawler.py is in the same directory")
    sys.exit(1)

async def quick_crawl_example():
    """Example of a quick domain crawl"""
    
    # Target domain (change this to your target)
    domain = "httpbin.org"  # Safe test domain
    
    print(f"🎯 Starting quick crawl of {domain}")
    
    # Skip subdomain discovery for quick example
    domains = {domain}
    
    print(f"📋 Crawling domain: {domain}")
    
    # Initialize crawler with modest settings
    crawler = WebCrawler(
        output_dir="results/quick_example",
        max_concurrent=3,
        timeout=15
    )
    
    # Start crawling
    print("🚀 Starting crawl...")
    results = await crawler.crawl_domains(domains)
    
    # Show summary
    print(f"\\n✅ Crawl completed!")
    print(f"   📊 Successfully crawled: {len(results)} pages")
    print(f"   ❌ Failed URLs: {len(crawler.failed_urls)}")
    print(f"   📁 Results saved to: {crawler.output_dir}")
    
    return results

if __name__ == "__main__":
    try:
        results = asyncio.run(quick_crawl_example())
        print("\\n🎉 Quick start example completed successfully!")
    except KeyboardInterrupt:
        print("\\n⏹️  Crawl interrupted by user")
    except Exception as e:
        print(f"\\n❌ Error: {e}")
        sys.exit(1)
'''

    # README file
    readme_md = '''# Domain Crawler with Screenshot Capture

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
'''

    # Create all files
    print("Extracting all files...")
    
    create_file("crawler.py", crawler_py, executable=True)
    create_file("requirements.txt", requirements_txt)
    create_file("crawler_config.py", crawler_config_py, executable=True)
    create_file("analyzer.py", analyzer_py, executable=True)
    create_file("setup.sh", setup_sh, executable=True)
    create_file("test_setup.py", test_setup_py, executable=True)
    create_file("quick_start.py", quick_start_py, executable=True)
    create_file("README.md", readme_md)
    
    print("\n" + "=" * 50)
    print("🎉 Domain Crawler Package Extracted Successfully!")
    print("=" * 50)
    print()
    print("Files created:")
    print("  ├── crawler.py           # Main crawler")
    print("  ├── analyzer.py          # Results analyzer")
    print("  ├── crawler_config.py    # Configuration manager")
    print("  ├── requirements.txt     # Python dependencies")
    print("  ├── setup.sh            # Setup script")
    print("  ├── test_setup.py       # Installation test")
    print("  ├── quick_start.py      # Quick example")
    print("  └── README.md           # Documentation")
    print()
    print("Next steps:")
    print("1. Make setup script executable: chmod +x setup.sh")
    print("2. Run setup: ./setup.sh")
    print("3. Activate environment: source crawler_env/bin/activate")
    print("4. Test installation: python test_setup.py")
    print("5. Try quick example: python quick_start.py")
    print()
    print("Happy crawling! 🕷️")

if __name__ == "__main__":
    extract_all_files()