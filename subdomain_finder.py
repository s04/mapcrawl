import dns.resolver
import requests
import argparse
import asyncio
import aiohttp
import json
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Set, Dict, Optional
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SubdomainFinder")

class SubdomainFinder:
    def __init__(self, domain: str, methods: List[str] = None, wordlist: str = None):
        """
        Initialize the subdomain finder.
        
        Args:
            domain: The target domain to find subdomains for
            methods: List of methods to use for finding subdomains
            wordlist: Path to a wordlist file for brute force method
        """
        self.domain = domain
        self.methods = methods or ["dns", "crt", "search", "bruteforce"]
        self.wordlist = wordlist
        self.subdomains: Set[str] = set()
        
    async def find_subdomains(self) -> Set[str]:
        """Run all enabled subdomain discovery methods and return results."""
        tasks = []
        
        if "dns" in self.methods:
            tasks.append(self.find_dns_subdomains())
            
        if "crt" in self.methods:
            tasks.append(self.find_certificate_subdomains())
            
        if "search" in self.methods:
            tasks.append(self.find_search_engine_subdomains())
            
        if "bruteforce" in self.methods and self.wordlist:
            tasks.append(self.bruteforce_subdomains())
            
        await asyncio.gather(*tasks)
        return self.subdomains
    
    async def find_dns_subdomains(self) -> None:
        """Find subdomains using DNS zone transfer and common DNS records."""
        logger.info(f"Searching for subdomains using DNS methods")
        
        try:
            # Try zone transfer (often blocked for security reasons)
            await self._try_zone_transfer()
            
            # Check common DNS records that might reveal subdomains
            common_prefixes = ["www", "mail", "ftp", "webmail", "login", "admin", 
                             "blog", "shop", "dev", "api", "staging", "test"]
            
            # Use ThreadPoolExecutor for DNS queries since they're blocking
            with ThreadPoolExecutor(max_workers=10) as executor:
                loop = asyncio.get_event_loop()
                tasks = []
                for prefix in common_prefixes:
                    tasks.append(loop.run_in_executor(
                        executor, 
                        self._check_dns_record, 
                        f"{prefix}.{self.domain}"
                    ))
                await asyncio.gather(*tasks)
                
        except Exception as e:
            logger.error(f"Error in DNS subdomain discovery: {e}")
            
    def _check_dns_record(self, hostname: str) -> None:
        """Check if a DNS record exists for a given hostname."""
        try:
            dns.resolver.resolve(hostname, 'A')
            self.subdomains.add(hostname)
            logger.info(f"Found subdomain via DNS: {hostname}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass  # Domain doesn't exist or no answer
        except Exception as e:
            logger.debug(f"Error checking DNS for {hostname}: {e}")
            
    async def _try_zone_transfer(self) -> None:
        """Attempt DNS zone transfer to get all subdomains."""
        try:
            # Get name servers for the domain
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            
            # Try zone transfer with each name server
            with ThreadPoolExecutor(max_workers=5) as executor:
                loop = asyncio.get_event_loop()
                tasks = []
                for ns in ns_records:
                    ns_hostname = str(ns.target).rstrip('.')
                    tasks.append(loop.run_in_executor(
                        executor, 
                        self._attempt_zone_transfer, 
                        ns_hostname
                    ))
                await asyncio.gather(*tasks)
                
        except Exception as e:
            logger.debug(f"Zone transfer error: {e}")
    
    def _attempt_zone_transfer(self, nameserver: str) -> None:
        """Attempt zone transfer against a specific nameserver."""
        try:
            xfr = dns.query.xfr(nameserver, self.domain)
            zone = dns.zone.from_xfr(xfr)
            for name, node in zone.nodes.items():
                hostname = f"{name}.{self.domain}"
                if hostname != self.domain:
                    self.subdomains.add(hostname)
                    logger.info(f"Found subdomain via zone transfer: {hostname}")
        except Exception as e:
            logger.debug(f"Zone transfer failed for {nameserver}: {e}")
    
    async def find_certificate_subdomains(self) -> None:
        """Find subdomains using SSL certificate transparency logs."""
        logger.info(f"Searching for subdomains using certificate transparency logs")
        
        # crt.sh API endpoint
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # crt.sh sometimes returns multiple subdomains with * and newlines
                            for hostname in name_value.split("\n"):
                                # Clean up the hostname
                                hostname = hostname.strip()
                                # Skip wildcard entries
                                if hostname.startswith('*.'):
                                    hostname = hostname[2:]
                                
                                # Verify it's a subdomain of our target
                                if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                                    self.subdomains.add(hostname)
                                    logger.info(f"Found subdomain via crt.sh: {hostname}")
        except Exception as e:
            logger.error(f"Error retrieving certificate info: {e}")
    
    async def find_search_engine_subdomains(self) -> None:
        """Find subdomains using search engines."""
        logger.info(f"Searching for subdomains using search engines")
        
        # Common search engine dorks
        queries = [
            f"site:{self.domain}",
            f"site:*.{self.domain}"
        ]
        
        # We'll use a free unofficial API for searching
        search_url = "https://api.duckduckgo.com/?q={}&format=json"
        
        for query in queries:
            try:
                encoded_query = requests.utils.quote(query)
                url = search_url.format(encoded_query)
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            try:
                                data = await response.json()
                                # Extract domains from the search results
                                self._extract_domains_from_search(data)
                            except json.JSONDecodeError:
                                text = await response.text()
                                self._extract_domains_from_html(text)
            except Exception as e:
                logger.error(f"Error searching for subdomains: {e}")
    
    def _extract_domains_from_search(self, data: Dict) -> None:
        """Extract domains from search engine JSON results."""
        # DuckDuckGo API format
        results = data.get('RelatedTopics', [])
        for result in results:
            if 'Result' in result:
                self._find_domains_in_text(result['Result'])
                
            if 'Topics' in result:
                for topic in result['Topics']:
                    if 'Result' in topic:
                        self._find_domains_in_text(topic['Result'])
    
    def _extract_domains_from_html(self, html: str) -> None:
        """Extract domains from HTML search results."""
        self._find_domains_in_text(html)
    
    def _find_domains_in_text(self, text: str) -> None:
        """Find domain names in text that match our target domain."""
        # This is a simple regex - could be improved for better matching
        pattern = r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.domain) + r')'
        for match in re.finditer(pattern, text):
            hostname = match.group(1)
            if hostname != self.domain:
                self.subdomains.add(hostname)
                logger.info(f"Found subdomain via search: {hostname}")
    
    async def bruteforce_subdomains(self) -> None:
        """Find subdomains by brute forcing with a wordlist."""
        logger.info(f"Brute forcing subdomains using wordlist")
        
        if not self.wordlist:
            logger.warning("No wordlist provided for brute force.")
            return
            
        try:
            # Read wordlist file
            with open(self.wordlist, 'r') as f:
                prefixes = [line.strip() for line in f if line.strip()]
                
            logger.info(f"Loaded {len(prefixes)} prefixes from wordlist")
            
            # Use semaphore to limit concurrent DNS requests
            semaphore = asyncio.Semaphore(20)
            
            async def check_subdomain(prefix):
                async with semaphore:
                    hostname = f"{prefix}.{self.domain}"
                    try:
                        # Use ThreadPoolExecutor for DNS queries since they're blocking
                        loop = asyncio.get_event_loop()
                        exists = await loop.run_in_executor(
                            None, self._check_dns_exists, hostname)
                        
                        if exists:
                            self.subdomains.add(hostname)
                            logger.info(f"Found subdomain via brute force: {hostname}")
                    except Exception as e:
                        logger.debug(f"Error checking {hostname}: {e}")
            
            # Create tasks for all prefixes
            tasks = [check_subdomain(prefix) for prefix in prefixes]
            await asyncio.gather(*tasks)
            
        except Exception as e:
            logger.error(f"Error in brute force: {e}")
    
    def _check_dns_exists(self, hostname: str) -> bool:
        """Check if a hostname has DNS records."""
        try:
            dns.resolver.resolve(hostname, 'A')
            return True
        except Exception:
            return False
            
    def verify_subdomains(self) -> Set[str]:
        """Verify discovered subdomains by checking if they're resolvable."""
        verified = set()
        for subdomain in self.subdomains:
            if self._check_dns_exists(subdomain):
                verified.add(subdomain)
        return verified


async def main():
    parser = argparse.ArgumentParser(description='Find subdomains for a given domain')
    parser.add_argument('domain', help='Target domain to find subdomains for')
    parser.add_argument('--methods', nargs='+', choices=['dns', 'crt', 'search', 'bruteforce'],
                        default=['dns', 'crt', 'search'], 
                        help='Methods to use for finding subdomains')
    parser.add_argument('--wordlist', help='Path to wordlist file for brute force method')
    parser.add_argument('--verify', action='store_true', help='Verify subdomains are resolvable')
    parser.add_argument('--output', help='Output file to save results')
    
    args = parser.parse_args()
    
    finder = SubdomainFinder(
        domain=args.domain,
        methods=args.methods,
        wordlist=args.wordlist
    )
    
    logger.info(f"Starting subdomain search for {args.domain}")
    subdomains = await finder.find_subdomains()
    
    if args.verify:
        logger.info("Verifying subdomains...")
        subdomains = finder.verify_subdomains()
    
    logger.info(f"Found {len(subdomains)} subdomains for {args.domain}")
    
    # Sort subdomains for consistent output
    sorted_subdomains = sorted(list(subdomains))
    
    # Print results
    for subdomain in sorted_subdomains:
        print(subdomain)
    
    # Save results if output file is specified
    if args.output:
        with open(args.output, 'w') as f:
            for subdomain in sorted_subdomains:
                f.write(f"{subdomain}\n")
        logger.info(f"Results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
    ## python subdomain_finder.py example.com --methods dns crt search --wordlist common_subdomains.txt --output results.txt
    ## python subdomain_finder.py example.com --methods crt
     