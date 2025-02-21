# WebScanner

一个功能强大的Web安全扫描工具，用于信息收集、漏洞检测和敏感数据发现。

---

## 简介

`webscanner.py` 是一个基于 Python 的异步Web扫描器，最初由 huocai 开发（GitHub: [huocai250](https://www.github.com/huocai250)），并由 Grok 3 增强至最终版。它集成了多种功能，包括基本信息收集、漏洞扫描、敏感信息检测和目录枚举，适用于安全研究、渗透测试和网站安全评估。

---

## 使用方法

运行脚本需要通过命令行参数指定目标URL和其他可选配置。基本格式如下：

```bash
python3 webscanner.py [-u url] [-t threads] [-w wordlist] [-o output] [-v] [-p proxy] [-r rate] [-s] [--no-robots] [--retries retries] [--custom-wordlist file]
```

---

## 依赖安装

运行脚本需要安装以下Python库。可以通过以下命令一次性安装：

```bash
pip install requests beautifulsoup4 tqdm aiohttp aiohttp_socks dnspython python-whois aiofiles aiohttp-retry pyjwt
```

---

## 依赖说明

```text
requests: 用于同步HTTP请求。
beautifulsoup4: 解析HTML内容。
tqdm: 显示扫描进度条。
aiohttp: 异步HTTP请求核心库。
aiohttp_socks: 支持SOCKS代理。
dnspython: DNS记录查询。
python-whois: WHOIS信息获取。
aiofiles: 异步文件操作。
aiohttp-retry: 提供请求重试功能。
pyjwt: 解码JWT令牌。
```

---

# 功能列表

---

## 基本信息收集

1.URL解析: 提取主机名、协议、IP、端口。

2.端口扫描: 检查常见端口（21, 22, 80, 443 等）并识别服务。

3.DNS记录: 查询 A、AAAA、MX、NS、TXT 等记录。

4.WHOIS信息: 获取域名注册信息。

5.子域名枚举: 使用内置或自定义字典发现子域名。

6.Robots.txt解析: 提取允许/禁止路径和Sitemap。

7.Sitemap解析: 解析XML格式，记录URL和优先级。

8.HTTP头分析: 检查安全头和服务器信息。

9.Cookie检查: 分析Cookie属性（Secure、HttpOnly等）。

10.SSL/TLS分析: 检查协议版本、加密算法和证书链。

11.CORS配置: 检测跨源资源共享设置。

12.HTTP方法: 检查支持的方法（如TRACE、CONNECT）。

13.服务器指纹: 识别CMS（如WordPress）和服务器类型。

---

## 漏洞扫描

14.XSS（跨站脚本）: 测试多种反射型XSS payload。

15.SQL注入: 检测错误型和时间盲注。

16.SSRF（服务器端请求伪造）: 检查内部服务访问。

17.LFI（本地文件包含）: 测试路径遍历漏洞。

18.RFI（远程文件包含）: 检测外部资源加载。

19.开放重定向: 检查URL跳转控制问题。

---

## 敏感信息检测

20.敏感数据扫描: 识别邮箱、电话、信用卡、API密钥、JWT等。

21.特殊处理: 解码JWT令牌。

---

##目录扫描

22.目录和文件枚举: 使用字典发现隐藏资源。

23.性能与隐蔽性

24.性能监控: 记录各模块耗时。

25.隐秘模式: 随机化头信息（如User-Agent、Referer）。
请求重试: 支持指数退避重试机制。

26.Robots.txt尊重: 可选遵守爬虫规则。

---

## 输出

27.结果保存: JSON格式，包含详细扫描数据。
