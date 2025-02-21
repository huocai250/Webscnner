以下是采用 GitHub Markdown（.md）格式对 webscanner.py 最终版的总结：
markdown
# WebScanner 使用说明

## 使用方法

运行脚本需要通过命令行参数指定目标URL和其他可选配置。基本格式如下：

```bash
python3 webscanner.py [-u url] [-t threads] [-w wordlist] [-o output] [-v] [-p proxy] [-r rate] [-s] [--no-robots] [--retries retries] [--custom-wordlist file]
命令行参数说明
参数
说明
是否必填
默认值
-u url
目标URL（例如 https://example.com）
是
无
-t threads
线程数
否
10
-w wordlist
目录扫描字典文件路径
否
dir.txt
-o output
输出结果文件路径（JSON格式）
否
无
-v
启用详细输出模式
否
False
-p proxy
代理地址（格式：http://host:port 或 socks5://host:port）
否
无
-r rate
每秒请求限制
否
100
-s
启用隐秘模式（随机头信息）
否
False
--no-robots
忽略 robots.txt 限制
否
True（尊重）
--retries retries
请求重试次数
否
3
--custom-wordlist file
自定义子域名/目录字典文件路径
否
无
功能列表
基本信息收集
URL解析: 提取主机名、协议、IP、端口。
端口扫描: 检查常见端口（21, 22, 80, 443 等）并识别服务。
DNS记录: 查询 A、AAAA、MX、NS、TXT 等记录。
WHOIS信息: 获取域名注册信息。
子域名枚举: 使用内置或自定义字典发现子域名。
Robots.txt解析: 提取允许/禁止路径和Sitemap。
Sitemap解析: 解析XML格式，记录URL和优先级。
HTTP头分析: 检查安全头和服务器信息。
Cookie检查: 分析Cookie属性（Secure、HttpOnly等）。
SSL/TLS分析: 检查协议版本、加密算法和证书链。
CORS配置: 检测跨源资源共享设置。
HTTP方法: 检查支持的方法（如TRACE、CONNECT）。
服务器指纹: 识别CMS（如WordPress）和服务器类型。
漏洞扫描
XSS（跨站脚本）: 测试多种反射型XSS payload。
SQL注入: 检测错误型和时间盲注。
SSRF（服务器端请求伪造）: 检查内部服务访问。
LFI（本地文件包含）: 测试路径遍历漏洞。
RFI（远程文件包含）: 检测外部资源加载。
开放重定向: 检查URL跳转控制问题。
敏感信息检测
敏感数据扫描: 识别邮箱、电话、信用卡、API密钥、JWT等。
特殊处理: 解码JWT令牌。
目录扫描
目录和文件枚举: 使用字典发现隐藏资源。
性能与隐蔽性
性能监控: 记录各模块耗时。
隐秘模式: 随机化头信息（如User-Agent、Referer）。
请求重试: 支持指数退避重试机制。
Robots.txt尊重: 可选遵守爬虫规则。
输出
结果保存: JSON格式，包含详细扫描数据。
依赖安装
运行脚本需要安装以下Python库。可以通过以下命令一次性安装：
bash
pip install requests beautifulsoup4 tqdm aiohttp aiohttp_socks dnspython python-whois aiofiles aiohttp-retry pyjwt
依赖说明
requests: HTTP请求库。
beautifulsoup4: HTML解析。
tqdm: 进度条显示。
aiohttp: 异步HTTP请求。
aiohttp_socks: 支持SOCKS代理。
dnspython: DNS查询。
python-whois: WHOIS信息查询。
aiofiles: 异步文件操作。
aiohttp-retry: 请求重试支持。
pyjwt: JWT令牌解码。
使用例子
基本用法
扫描目标并输出到控制台：
bash
python3 webscanner.py -u https://example.com
详细输出并保存结果
启用详细模式并保存到JSON文件：
bash
python3 webscanner.py -u https://example.com -v -o results.json
使用代理和隐秘模式
通过SOCKS5代理扫描，启用隐秘模式：
bash
python3 webscanner.py -u https://example.com -p socks5://127.0.0.1:9050 -s -v
自定义字典和线程
指定目录字典、子域名字典和线程数，调整请求速率：
bash
python3 webscanner.py -u https://example.com -t 20 -w dir.txt --custom-wordlist subdomains.txt -r 50 -v -o scan_results.json
高级配置
忽略robots.txt，设置重试次数，使用代理：
bash
python3 webscanner.py -u https://example.com -t 15 -w custom_dirs.txt -p http://proxy.example.com:8080 -r 75 -s --no-robots --retries 5 -v -o detailed_results.json
输出示例
以下是运行 python3 webscanner.py -u https://example.com -v -o results.json 的部分输出：
plaintext
2025-02-21 10:00:00,123 - INFO - --------------------[*] URL基本检测加载中...--------------------
2025-02-21 10:00:00,124 - INFO - [+] 域名: example.com
2025-02-21 10:00:00,125 - INFO - [+] 协议: https
2025-02-21 10:00:00,126 - INFO - [+] IP地址: 93.184.216.34
2025-02-21 10:00:00,127 - INFO - [+] 默认端口: 443
2025-02-21 10:00:00,128 - INFO - [+] 开放端口: 80 (http), 443 (https)
2025-02-21 10:00:00,129 - INFO - [+] HTTP头信息:
2025-02-21 10:00:00,130 - INFO -     Server: nginx
2025-02-21 10:00:00,131 - WARNING - [!] 缺少安全头: Content-Security-Policy
2025-02-21 10:00:00,132 - INFO - [+] Cookies:
2025-02-21 10:00:00,133 - INFO -     session_id: abc123 (Secure: True)
2025-02-21 10:00:00,134 - INFO - [+] 发现子域名: www.example.com, mail.example.com
2025-02-21 10:00:00,135 - INFO - --------------------[*] XSS检测加载中...--------------------
2025-02-21 10:00:00,136 - INFO - [+] 在 https://example.com 上检测到 2 个表单
2025-02-21 10:00:00,137 - INFO - [+] 检测到敏感信息 (email): test@example.com
2025-02-21 10:00:02,138 - INFO - 扫描完成，用时: 2.21 秒
2025-02-21 10:00:02,139 - INFO - 结果已保存到 results.json
生成的 results.json 文件将包含所有扫描数据，格式详见代码中的完整示例。
这个最终版Web扫描器功能全面，适用于安全研究和渗透测试。通过灵活的配置，用户可以根据需求调整扫描深度和隐蔽性。
```