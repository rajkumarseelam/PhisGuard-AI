#!/usr/bin/env python3
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
