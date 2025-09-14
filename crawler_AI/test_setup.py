#!/usr/bin/env python3
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
        print("\n🎉 Installation test successful!")
        print("   Run 'python crawler.py example.com --skip-subdomains' to try the crawler")
    else:
        print("\n❌ Installation test failed!")
        print("   Please check the installation steps")
