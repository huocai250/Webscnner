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