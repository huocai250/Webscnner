"""
by huocai
qq 1332334007
"""
import urllib
import sys
import time
import requests
import urllib.request
from scapy.all import *
from optparse import OptionParser
from urllib.parse import urlparse
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin



# 获取url的相关信息
def Parseurl(url):
    _url = urlparse(url)
    hostname = _url.hostname
    url_protocol = _url.scheme
    opener = urllib.request.build_opener()
    response = opener.open(url, timeout=1000)
    ip_port = response.fp.raw._sock.getpeername()
    print("-" * 20 + "[*]URL基本检测加载中...    请等待" + "-" * 20)
    print(f'[+]域名:{hostname}\n[+]域名协议:{url_protocol}\n[+]ip和端口{ip_port}')


def get_all_forms(url):
    """传递url，建立链接"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    建立表单
    """
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)


def scan_xss(url):
    forms = get_all_forms(url)
    print("-" * 20 + "[*]XSS检测加载中...    请等待" + "-" * 20)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    is_vulnerable = False
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print("-" * 20 + "[*]XSS检测加载中...    请等待" + "-" * 20)
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True


def scnnerwebfile(url):
    file = open("dir.txt", "r")
    print("-" * 20 + "[*]网站目录加载中...    请等待" + "-" * 20)
    print("该网站存在以下目录")
    for line in file.readlines():  # 读字典中的每一行
        line = line.strip()  # 每行默认会有\n，只是不显示，调用strip将其忽略
        fileurl = url + line  # 需要测试的url
        response = requests.get(fileurl)
        if response.status_code == 200:  # 如果响应码为200 则该目录存在
            print(fileurl)
    file.close()


def main():
    # 使用提示
    usage = 'sudo python3 webscnner.py [-u url]\nby huocai 此项目不开源！！！\n作者QQ:1332334007'
    parser = OptionParser(usage)

    parser.add_option('-u', dest='url', type='string', help='链接')

    # 解析命令行
    (options, args) = parser.parse_args()
    if len(args) != options.url is None:
        # 输出使用提示
        parser.print_help()
        sys.exit(0)


    # 获取url链接
    url = options.url

    # 输出扫描内容
    Parseurl(url)
    print(scan_xss(url))
    scnnerwebfile(url)


if __name__ == "__main__":
    main()
