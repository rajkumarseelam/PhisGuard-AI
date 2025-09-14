#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Domain Crawler with Screenshot Capture
=====================================

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
                                for name in name_value.split('\n'):
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
                    subdomains = stdout.decode().strip().split('\n')
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
                 timeout: int = 30, user_agent: str = None, max_depth: int = 2):
        self.output_dir = Path(output_dir)
        self.screenshots_dir = self.output_dir / "screenshots"
        self.content_dir = self.output_dir / "content"
        self.data_dir = self.output_dir / "data"
        
        # Create depth-specific directories
        for depth in range(max_depth + 1):
            (self.screenshots_dir / f"depth_{depth}").mkdir(parents=True, exist_ok=True)
            (self.content_dir / "text" / f"depth_{depth}").mkdir(parents=True, exist_ok=True)
            (self.content_dir / "html" / f"depth_{depth}").mkdir(parents=True, exist_ok=True)
        
        # Create main directories
        for dir_path in [self.output_dir, self.content_dir, self.data_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.max_depth = max_depth
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
        """Main method to crawl all domains using BFS with depth control"""
        logger.info(f"Starting BFS crawl of {len(domains)} domains (max depth: {self.max_depth})")
        
        visited = set()
        queue = []
        
        # Extract base domain for filtering (e.g., "sbi" from "onlinesbi.sbi")
        base_domain = None
        for domain in domains:
            extracted = tldextract.extract(domain)
            if extracted.domain:
                base_domain = extracted.domain
                break
        
        # Initialize queue with starting domains at depth 0
        for domain in domains:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{domain}"
                queue.append((url, 0))  # (url, depth)
        
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
                semaphore = asyncio.Semaphore(self.max_concurrent)
                
                while queue:
                    # Process current depth level
                    current_batch = []
                    next_queue = []
                    
                    # Collect all URLs at current depth
                    while queue and len(current_batch) < self.max_concurrent:
                        url, depth = queue.pop(0)
                        if url not in visited and depth <= self.max_depth:
                            current_batch.append((url, depth))
                            visited.add(url)
                    
                    if not current_batch:
                        break
                    
                    # Process batch concurrently
                    tasks = []
                    for url, depth in current_batch:
                        tasks.append(self._crawl_and_extract_links(browser, semaphore, url, depth, base_domain))
                    
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Collect new links for next depth
                    for result in results:
                        if isinstance(result, list):  # List of new URLs
                            for new_url, new_depth in result:
                                if new_url not in visited and new_depth <= self.max_depth:
                                    queue.append((new_url, new_depth))
                    
            finally:
                await browser.close()
        
        # Save results
        await self._save_results()
        
        logger.info(f"BFS crawling completed. Processed {len(self.results)} pages, "
                   f"failed on {len(self.failed_urls)} URLs")
        
        return self.results
    
    async def _crawl_and_extract_links(self, browser: Browser, semaphore: asyncio.Semaphore, url: str, depth: int, base_domain: str) -> List[Tuple[str, int]]:
        """Crawl a single URL and return new links for next depth"""
        new_links = []
        
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
                        result = await self._extract_page_data(page, url, depth)
                        
                        if result:
                            self.results.append(result)
                            logger.info(f"Successfully crawled (depth {depth}): {url}")
                            
                            # Extract links for next depth
                            if depth < self.max_depth:
                                links = result.get('links', [])
                                for link in links:
                                    link_url = link.get('url')
                                    if link_url and self._is_valid_link(link_url, base_domain):
                                        new_links.append((link_url, depth + 1))
                        
                    except Exception as e:
                        self.failed_urls.append({"url": url, "error": str(e), "depth": depth})
                        logger.warning(f"Failed to crawl {url} (depth {depth}): {e}")
                    
                    finally:
                        await context.close()
                        
                except Exception as e:
                    self.failed_urls.append({"url": url, "error": str(e), "depth": depth})
                    logger.error(f"Browser error for {url} (depth {depth}): {e}")
        
        return new_links
    
    def _is_valid_link(self, url: str, base_domain: str) -> bool:
        """Check if a link should be crawled based on domain filtering"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False
            
            # Extract domain parts
            extracted = tldextract.extract(url)
            
            # Allow crawling if:
            # 1. Same base domain (e.g., any *.sbi domain)
            # 2. Contains the base domain in the domain part
            return (extracted.domain == base_domain or 
                    base_domain in extracted.domain or 
                    extracted.domain in base_domain)
            
        except Exception:
            return False

    async def _extract_page_data(self, page: Page, url: str, depth: int = 0) -> Optional[Dict]:
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
            
            # Take screenshot in depth-specific directory
            screenshot_filename = self._generate_filename(final_url, "png")
            screenshot_path = self.screenshots_dir / f"depth_{depth}" / screenshot_filename
            
            await page.screenshot(
                path=str(screenshot_path),
                full_page=True,
                type='png'
            )
            
            # Save text content to depth-specific directory
            content_filename = self._generate_filename(final_url, "txt")
            content_path = self.content_dir / "text" / f"depth_{depth}" / content_filename
            
            async with aiofiles.open(content_path, 'w', encoding='utf-8') as f:
                await f.write(text_content)
            
            # Save raw HTML to depth-specific directory
            html_filename = self._generate_filename(final_url, "html")
            html_path = self.content_dir / "html" / f"depth_{depth}" / html_filename
            
            async with aiofiles.open(html_path, 'w', encoding='utf-8') as f:
                await f.write(content)
            
            # Create result object
            result = {
                "url": final_url,
                "original_url": url,
                "title": title,
                "depth": depth,
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
                "links": links,  # Keep all links for BFS
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
        base_name = re.sub(r'[<>:"/\\|?*]', '_', base_name)
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
        
        csv_content = "URL,Title,Status,Text Length,Links Count,Images Count,Screenshot Path\n"
        for result in self.results:
            csv_content += f"\"{result['url']}\",\"{result['title']}\",200,{result['text_length']},{result['links_count']},{result['images_count']},\"{result['screenshot_path']}\"\n"
        
        async with aiofiles.open(csv_file, 'w', encoding='utf-8') as f:
            await f.write(csv_content)
        
        logger.info(f"CSV summary saved to {csv_file}")

async def main():
    """Main function to run the domain crawler"""
    parser = argparse.ArgumentParser(description="Domain Crawler with Screenshot Capture (BFS)")
    parser.add_argument("domain", help="Target domain to crawl")
    parser.add_argument("-o", "--output", default="crawl_results", help="Output directory")
    parser.add_argument("-c", "--concurrent", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Page load timeout in seconds")
    parser.add_argument("-d", "--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
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
    
    logger.info(f"Starting BFS domain crawl for: {domain} (max depth: {args.max_depth})")
    
    # Discover subdomains
    domains_to_crawl = set()
    
    if args.skip_subdomains:
        domains_to_crawl.add(domain)
    else:
        subdomain_discovery = SubdomainDiscovery(domain)
        domains_to_crawl = await subdomain_discovery.discover_subdomains()
    
    logger.info(f"Found {len(domains_to_crawl)} domains to crawl")
    
    # Initialize crawler with BFS parameters
    crawler = WebCrawler(
        output_dir=args.output,
        max_concurrent=args.concurrent,
        timeout=args.timeout,
        user_agent=args.user_agent,
        max_depth=args.max_depth
    )
    
    # Start BFS crawling
    start_time = time.time()
    results = await crawler.crawl_domains(domains_to_crawl)
    end_time = time.time()
    
    # Print organized summary
    print(f"\n{'='*60}")
    print(f"BFS CRAWL SUMMARY")
    print(f"{'='*60}")
    print(f"Target Domain: {domain}")
    print(f"Subdomains Found: {len(domains_to_crawl)}")
    print(f"Max Depth: {args.max_depth}")
    print(f"Successful Pages: {len(results)}")
    print(f"Failed URLs: {len(crawler.failed_urls)}")
    print(f"Total Time: {end_time - start_time:.2f} seconds")
    print(f"Output Directory: {crawler.output_dir}")
    print()
    
    # Show depth distribution
    depth_counts = {}
    for result in results:
        depth = result.get('depth', 0)
        depth_counts[depth] = depth_counts.get(depth, 0) + 1
    
    print("Pages by Depth:")
    for depth in sorted(depth_counts.keys()):
        print(f"  Depth {depth}: {depth_counts[depth]} pages")
    
    print()
    print("Output Structure:")
    print(f"  ├── screenshots/")
    for depth in sorted(depth_counts.keys()):
        print(f"  │   └── depth_{depth}/ ({depth_counts[depth]} PNG files)")
    print(f"  ├── content/")
    print(f"  │   ├── text/")
    for depth in sorted(depth_counts.keys()):
        print(f"  │   │   └── depth_{depth}/ ({depth_counts[depth]} TXT files)")
    print(f"  │   └── html/")
    for depth in sorted(depth_counts.keys()):
        print(f"  │       └── depth_{depth}/ ({depth_counts[depth]} HTML files)")
    print(f"  └── data/ (JSON and CSV summaries)")
    print(f"{'='*60}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Crawl interrupted by user")
    except Exception as e:
        logger.error(f"Crawl failed: {e}")
        sys.exit(1) 