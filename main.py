import requests
import xml.etree.ElementTree as ET
import logging
import asyncio
import re
import urllib.parse
from typing import List, Set, Callable, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
import aiohttp
from urllib.parse import urlparse
import datetime
import json

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SitemapCrawler")

@dataclass
class CrawlerOptions:
    """Options for configuring the crawler behavior."""
    includes: List[str] = field(default_factory=list)
    excludes: List[str] = field(default_factory=list)
    max_depth: int = 2
    limit: int = 10
    ignore_sitemap: bool = True
    allow_backward_links: bool = False
    allow_external_links: bool = False
    regex_on_full_url: bool = False

@dataclass
class ScrapeOptions:
    """Options for configuring the scraper behavior."""
    only_main_content: bool = True
    include_tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    wait_for: int = 0
    timeout: int = 60000
    formats: List[str] = field(default_factory=lambda: ["markdown"])

class TimeoutSignal(Exception):
    """Exception raised when a timeout occurs."""
    pass

class SitemapCrawler:
    def __init__(self, 
                 job_id: str, 
                 initial_url: str,
                 crawler_options: Optional[CrawlerOptions] = None,
                 scrape_options: Optional[ScrapeOptions] = None):
        """
        Initialize the sitemap crawler.
        
        Args:
            job_id: Unique identifier for this crawl job
            initial_url: The starting URL to crawl
            crawler_options: Configuration options for crawling behavior
            scrape_options: Configuration options for scraping behavior
        """
        self.job_id = job_id
        self.initial_url = initial_url
        self.base_url = self._get_base_url(initial_url)
        self.crawler_options = crawler_options or CrawlerOptions()
        self.scrape_options = scrape_options or ScrapeOptions()
        
        # Internal state
        self.visited: Set[str] = set()
        self.crawled_urls: Dict[str, str] = {}
        self.robots_txt_url = f"{self.base_url}/robots.txt"
        self.robots_content = ""
        self.sitemaps_hit: Set[str] = set()
        
        # Compile regex patterns for includes and excludes
        self.include_patterns = [re.compile(pattern) for pattern in self.crawler_options.includes]
        self.exclude_patterns = [re.compile(pattern) for pattern in self.crawler_options.excludes]

    def _get_base_url(self, url: str) -> str:
        """Extract the base URL (scheme + netloc) from a full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def is_file(self, url: str) -> bool:
        """Check if a URL points to a file rather than a webpage."""
        file_extensions = [
            ".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico", ".svg", ".tiff",
            ".zip", ".exe", ".dmg", ".mp4", ".mp3", ".wav", ".pptx", ".xlsx",
            ".avi", ".flv", ".woff", ".ttf", ".woff2", ".webp", ".inc"
        ]
        
        try:
            url_without_query = url.split("?")[0].lower()
            return any(url_without_query.endswith(ext) for ext in file_extensions)
        except Exception as error:
            logger.error(f"Error in is_file: {error}")
            return False

    def get_url_depth(self, url: str) -> int:
        """Calculate the depth of a URL relative to the base URL."""
        try:
            parsed_url = urlparse(url)
            path_parts = [part for part in parsed_url.path.split('/') if part]
            return len(path_parts)
        except Exception as error:
            logger.error(f"Error calculating URL depth: {error}")
            return 0

    def filter_links(self, links: List[str], limit: int, max_depth: int, from_map: bool = False) -> List[str]:
        """
        Filter links based on includes, excludes, depth, and other criteria.
        
        Args:
            links: List of URLs to filter
            limit: Maximum number of links to return
            max_depth: Maximum depth of links to include
            from_map: Whether these links came from a sitemap
            
        Returns:
            Filtered list of URLs
        """
        # Special case: if initial URL is sitemap.xml
        if self.initial_url.endswith("sitemap.xml") and from_map:
            return links[:limit]
        
        filtered_links = []
        for link in links:
            try:
                # Clean and parse the URL
                link = link.strip()
                try:
                    url_obj = urlparse(link)
                    if not url_obj.scheme:
                        # Relative URL, make it absolute
                        link = urllib.parse.urljoin(self.base_url, link)
                        url_obj = urlparse(link)
                except Exception:
                    logger.debug(f"Error processing link: {link}")
                    continue
                
                # Check depth
                depth = self.get_url_depth(link)
                if depth > max_depth:
                    logger.debug(f"{link} DEPTH FAIL")
                    continue
                
                # Check includes and excludes
                path = url_obj.path
                check_path = link if self.crawler_options.regex_on_full_url else path
                
                # Check excludes
                if self.crawler_options.excludes:
                    if any(pattern.search(check_path) for pattern in self.exclude_patterns):
                        logger.debug(f"{link} EXCLUDE FAIL")
                        continue
                
                # Check includes
                if self.crawler_options.includes:
                    if not any(pattern.search(check_path) for pattern in self.include_patterns):
                        logger.debug(f"{link} INCLUDE FAIL")
                        continue
                
                # Check if backwards navigation is allowed
                if not self.crawler_options.allow_backward_links:
                    initial_path = urlparse(self.initial_url).path
                    if not path.startswith(initial_path):
                        logger.debug(f"{link} BACKWARDS FAIL {path} {initial_path}")
                        continue
                
                # Check if it's a file
                if self.is_file(link):
                    logger.debug(f"{link} FILE FAIL")
                    continue
                
                # Link passed all filters
                logger.debug(f"{link} OK")
                filtered_links.append(link)
                
                if len(filtered_links) >= limit:
                    break
                    
            except Exception as e:
                logger.error(f"Error filtering link {link}: {e}")
        
        return filtered_links

    async def fetch_robots_txt(self) -> str:
        """Fetch the robots.txt file for the domain."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.robots_txt_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        self.robots_content = content
                        return content
                    else:
                        logger.warning(f"Failed to fetch robots.txt: HTTP {response.status}")
                        return ""
        except Exception as e:
            logger.error(f"Error fetching robots.txt: {e}")
            return ""

    def parse_robots_txt(self, content: str) -> List[str]:
        """
        Parse robots.txt content to extract sitemap URLs.
        
        Returns:
            List of sitemap URLs found in robots.txt
        """
        sitemaps = []
        for line in content.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemap_url = line[8:].strip()
                sitemaps.append(sitemap_url)
        return sitemaps

    async def fetch_sitemap(self, sitemap_url: str) -> str:
        """
        Fetch a sitemap file.
        
        Args:
            sitemap_url: URL of the sitemap to fetch
            
        Returns:
            The sitemap content as a string
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(sitemap_url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.text()
                        logger.debug(f"Fetched sitemap {sitemap_url} with content length: {len(content)}")
                        return content
                    else:
                        logger.error(f"Failed to fetch sitemap {sitemap_url}: HTTP {response.status}")
                        return ""
        except aiohttp.ClientError as e:
            logger.error(f"Request error fetching sitemap {sitemap_url}: {e}")
            return ""
        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching sitemap {sitemap_url}")
            raise TimeoutSignal()

    async def process_sitemap_content(self, 
                                     content: str, 
                                     urls_handler: Callable[[List[str]], Any]) -> int:
        """
        Process sitemap XML content to extract URLs.
        
        Args:
            content: XML content of the sitemap
            urls_handler: Callback function to process found URLs
            
        Returns:
            Number of URLs found
        """
        if not content:
            logger.debug("Empty sitemap content received")
            return 0
            
        try:
            # Parse XML content
            root = ET.fromstring(content)
            
            # Namespace handling
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            
            # Check if this is a sitemap index
            sitemaps = root.findall(".//sm:sitemap/sm:loc", ns)
            if sitemaps:
                # This is a sitemap index
                sitemap_urls = [sitemap_loc.text.strip() for sitemap_loc in sitemaps if sitemap_loc.text]
                logger.debug(f"Found sitemap index with {len(sitemap_urls)} sitemaps")
                count = 0
                for sitemap_url in sitemap_urls:
                    count += await self.get_links_from_sitemap(sitemap_url, urls_handler)
                return count
                
            # Regular sitemap with URLs
            url_elements = root.findall(".//sm:url/sm:loc", ns)
            if not url_elements:
                # Try without namespace (some sitemaps don't use namespaces)
                url_elements = root.findall(".//url/loc")
                logger.debug(f"Tried without namespace, found {len(url_elements)} URL elements")
                
            if url_elements:
                urls = [url_loc.text.strip() for url_loc in url_elements if url_loc.text]
                logger.debug(f"Found {len(urls)} URLs in sitemap")
                
                # Filter out sitemap XML files and known file types
                xml_sitemaps = [url for url in urls if url.lower().endswith('.xml')]
                regular_urls = [url for url in urls if not url.lower().endswith('.xml') and not self.is_file(url)]
                logger.debug(f"After filtering: {len(xml_sitemaps)} XML sitemaps, {len(regular_urls)} regular URLs")
                
                # Process additional sitemaps if found
                count = 0
                for xml_sitemap in xml_sitemaps:
                    count += await self.get_links_from_sitemap(xml_sitemap, urls_handler)
                
                # Process regular URLs
                if regular_urls:
                    await urls_handler(regular_urls)
                    count += len(regular_urls)
                    
                return count
                
            return 0
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return 0
        except Exception as e:
            logger.error(f"Error processing sitemap content: {e}")
            return 0

    async def get_links_from_sitemap(self, 
                                    sitemap_url: str, 
                                    urls_handler: Callable[[List[str]], Any]) -> int:
        """
        Fetch and process a sitemap to extract URLs.
        
        Args:
            sitemap_url: URL of the sitemap to process
            urls_handler: Callback function to process found URLs
            
        Returns:
            Number of URLs found
        """
        # Prevent excessive sitemap requests
        if len(self.sitemaps_hit) >= 20:
            logger.warning(f"Maximum number of sitemaps (20) already processed")
            return 0
            
        # Prevent duplicate sitemap processing
        if sitemap_url in self.sitemaps_hit:
            logger.warning(f"Sitemap already processed: {sitemap_url}")
            return 0
            
        self.sitemaps_hit.add(sitemap_url)
        
        try:
            # Ensure sitemap URL ends with .xml
            if not sitemap_url.endswith('.xml'):
                sitemap_url = f"{sitemap_url.rstrip('/')}/sitemap.xml"
                
            logger.info(f"Fetching sitemap: {sitemap_url}")
            content = await self.fetch_sitemap(sitemap_url)
            
            if content:
                logger.debug(f"Successfully fetched sitemap content from {sitemap_url}, processing...")
                result = await self.process_sitemap_content(content, urls_handler)
                logger.debug(f"Processed sitemap {sitemap_url}, found {result} URLs")
                return result
            else:
                logger.debug(f"No content returned from sitemap {sitemap_url}")
            return 0
            
        except TimeoutSignal:
            raise  # Re-raise timeout signal to be handled by caller
        except Exception as e:
            logger.error(f"Error processing sitemap {sitemap_url}: {e}")
            return 0

    async def try_get_sitemap(self, 
                             urls_handler: Callable[[List[str]], Any],
                             from_map: bool = False,
                             only_sitemap: bool = False,
                             timeout: int = 120000) -> int:
        """
        Main entry point to crawl sitemaps.
        
        Args:
            urls_handler: Callback to process found URLs
            from_map: Whether we're handling URLs from a sitemap
            only_sitemap: Only return sitemap URLs without additional filtering
            timeout: Maximum time to spend on sitemap processing in milliseconds
            
        Returns:
            Number of URLs found
        """
        logger.info(f"Fetching sitemap links from {self.initial_url}")
        left_of_limit = self.crawler_options.limit
        
        # Create a handler that respects the limit
        async def _urls_handler(urls: List[str]):
            nonlocal left_of_limit
            
            if from_map and only_sitemap:
                return await urls_handler(urls)
            else:
                # Filter links
                filtered_links = self.filter_links(
                    list(set(urls)),
                    left_of_limit,
                    self.crawler_options.max_depth,
                    from_map
                )
                left_of_limit -= len(filtered_links)
                
                if filtered_links:
                    # Check if urls_handler is a coroutine function
                    result = urls_handler(filtered_links)
                    if asyncio.iscoroutine(result):
                        return await result
                    return result
            
        # Set up timeout
        try:
            # First, get robots.txt to find potential sitemaps
            robots_content = await self.fetch_robots_txt()
            sitemap_urls = self.parse_robots_txt(robots_content)
            
            # Always check the initial URL as a potential sitemap
            sitemap_tasks = [asyncio.create_task(self.get_links_from_sitemap(self.initial_url, _urls_handler))]
            
            # Add all sitemaps found in robots.txt
            for sitemap_url in sitemap_urls:
                sitemap_tasks.append(asyncio.create_task(self.get_links_from_sitemap(sitemap_url, _urls_handler)))
                
            # Create a timeout task
            timeout_task = asyncio.create_task(asyncio.sleep(timeout / 1000))
            
            # Wait for either all sitemap tasks to complete or timeout
            done, pending = await asyncio.wait(
                sitemap_tasks + [timeout_task],
                return_when=asyncio.ALL_COMPLETED,
                timeout=30  # Add a timeout of 30 seconds
            )
            
            logger.debug(f"Completed {len(done)} tasks, {len(pending)} tasks pending")
            
            # Cancel the timeout task if it's still pending
            if timeout_task in pending:
                timeout_task.cancel()
            
            # Cancel any remaining tasks
            for task in pending:
                if task is not timeout_task:
                    task.cancel()
                
            # Process results
            results = []
            for task in done:
                if task is not timeout_task:
                    try:
                        result = task.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Task error: {e}")
                        
            count = sum(results)
            logger.debug(f"Found {count} URLs from completed tasks")
            
            # Also add the initial URL if we found something
            if count > 0:
                await urls_handler([self.initial_url])
                count += 1
                
            return count
            
        except Exception as e:
            logger.error(f"Error in try_get_sitemap: {e}")
            return 0

    async def crawl(self) -> List[str]:
        """
        Execute the sitemap crawl and return all discovered URLs.
        
        Returns:
            List of discovered URLs
        """
        discovered_urls = []
        
        async def collect_urls(urls: List[str]):
            discovered_urls.extend(urls)
            
        if not self.crawler_options.ignore_sitemap:
            await self.try_get_sitemap(collect_urls)
            
        return discovered_urls


# Example usage
async def main():
    crawler = SitemapCrawler(
        job_id="test-crawl-1", 
        initial_url="https://cloudflare.com",
        crawler_options=CrawlerOptions(
            includes=[],  # No includes to get all URLs
            excludes=[],  # No excludes
            max_depth=2,  # High depth
            limit=100000,  # Very high limit to get all URLs
            ignore_sitemap=False,
            allow_backward_links=True,
            allow_external_links=True
        )
    )
    
    urls = []
    
    # Create a file to save URLs as they're discovered
    with open("all_urls.txt", "w") as url_file:
        url_file.write(f"# Crawl started at {datetime.datetime.now()}\n")
        url_file.write(f"# Initial URL: {crawler.initial_url}\n\n")
        
        async def save_urls(found_urls):
            # Add to our in-memory list
            urls.extend(found_urls)
            
            # Also write to file immediately to ensure we don't lose data
            with open("all_urls.txt", "a") as f:
                for url in found_urls:
                    f.write(f"{url}\n")
            
            print(f"Found {len(found_urls)} URLs")
        
        # Try to get URLs from the sitemap
        count = await crawler.try_get_sitemap(save_urls, only_sitemap=True)
        
        # Write summary at the end of the file
        with open("all_urls.txt", "a") as f:
            f.write(f"\n# Total discovered URLs: {len(urls)}\n")
            f.write(f"# Crawl completed at {datetime.datetime.now()}\n")
    
    print(f"Total discovered URLs: {count}")
    print(f"All URLs have been saved to all_urls.txt")
    
    # Also save as JSON for programmatic access
    output_file = "discovered_urls.json"
    with open(output_file, "w") as f:
        json.dump({
            "total_count": len(urls),
            "initial_url": crawler.initial_url,
            "timestamp": str(datetime.datetime.now()),
            "urls": urls
        }, f, indent=2)
    
    print(f"URLs also saved to {output_file}")

if __name__ == "__main__":
    asyncio.run(main())