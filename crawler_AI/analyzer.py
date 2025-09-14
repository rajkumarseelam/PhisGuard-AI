#!/usr/bin/env python3
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
        report_text = "\n".join(report)
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
    
    print(f"\nAnalysis completed. Report saved to: {report_file}")

if __name__ == "__main__":
    main()
