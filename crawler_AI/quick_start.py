#!/usr/bin/env python3
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
    print(f"\n✅ Crawl completed!")
    print(f"   📊 Successfully crawled: {len(results)} pages")
    print(f"   ❌ Failed URLs: {len(crawler.failed_urls)}")
    print(f"   📁 Results saved to: {crawler.output_dir}")
    
    return results

if __name__ == "__main__":
    try:
        results = asyncio.run(quick_crawl_example())
        print("\n🎉 Quick start example completed successfully!")
    except KeyboardInterrupt:
        print("\n⏹️  Crawl interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
