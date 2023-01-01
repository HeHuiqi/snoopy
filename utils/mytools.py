#! /usr/bin/env python
# -*- coding:utf-8 -*-
'''
@Author:Sunqh
@FileName: *.py
@Version:1.0.0

'''
import hashlib
import random
import re
import time

from utils import logger


def get_current_timestamp():
    # print(time.time())
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
    # print(ts)
    return ts

def is_email(email):
    email_list = re.findall("^[A-ZA-z0-9]{1,30}@[A-ZA-z0-9]{1,10}\.[a-zA-Z]{1,10}$", email)
    if email_list:
        return True
    else:
        return False

def is_phone(phone):
    phone_list = re.findall("^\d{11}$", phone)
    if phone_list:
        return True
    else:
        return False

def is_CVE_or_CNVD_or_CNNVD(data, msg_type=None):
    if msg_type == "CVE":
        res_list = re.findall("CVE-\d(1,6)-\d{1,10}", data)
    elif msg_type == "CNVD":
        res_list = re.findall("CNVD-\d(1,6)-\d{1,10}", data)
    elif msg_type == "CNNVD":
        res_list = re.findall("CNNVD-\d(1,6)-\d{1,10}", data)
    else:
        return False
    if len(res_list) > 0:
        return True
    else:
        return False

def get_random_password():

    char_string = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'

    salt = ''
    for i in range(15):
        salt += random.choice(char_string)

    return salt

def get_hash_8bit_md5(field=None, objects=None):
    if field == "vuln_id" or field == "bug_id":
        name_list = []
        for obj in objects:
            if field == "vuln_id":
                name_list.append(obj.vuln_id)
            if field == "bug_id":
                name_list.append(obj.bug_id)
        while True:
            hashmd5 = hashlib.md5(str(time.time()).encode("utf-8")).hexdigest()[:16]
            if hashmd5 not in name_list:
                return hashmd5
    else:
        hashmd5 = hashlib.md5(str(time.time()).encode("utf-8")).hexdigest()[:16]
    return hashmd5


if __name__ == "__main__":
    get_current_timestamp()