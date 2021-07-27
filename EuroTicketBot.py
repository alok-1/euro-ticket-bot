# -*- coding: utf-8 -*-
import csv
import requests
from bs4 import BeautifulSoup
import random
import time
from datetime import datetime, timedelta
from datetime import time as tme
import string
import os
import lxml
import imghdr
import threading
import traceback
import mysql.connector
from datetime import datetime, timedelta
from datetime import time as tme
import io
import ssl
import json
import base64
import copy
import smtplib
import sys
import _thread
#import thread
import threading
import urllib
#import urllib3
#from urllib.parse import urlencode, quote
from requests_toolbelt.multipart.encoder import MultipartEncoder
import shutil
from random import randint
#from PIL import Image

StopBot = False
Queue_Token = ''
Queue_Token_Available = False
Queue_Available = True


config = {
    'user': 'user',
    'password': 'Password',
    'host': 'hostname',
    'database': 'database',
    'raise_on_warnings': True,
}


class Users():

    def __init__(self, email, password, status):
        self.email = email
        self.password = password
        self.status = status


class Proxies():

    def __init__(self, host, port, username, password):
        self.host = ip
        self.port = port
        self.username = username
        self.password = password


class Cards():

    def __init__(self, holder, cardnumber, cvv, expm, expy):
        self.holder = holder
        self.cardnumber = cardnumber
        self.cvv = cvv
        self.expm = expm
        self.expy = expy


USERS = []
PROXIES = []
LOG_ROWS = []
CARDS = []

#import pytesseract
#path_to_tesseract = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
#image_path = r"img.png"

#prx = {'http':'127.0.0.1:8888', 'https': '127.0.0.1:8888'}


ticket_quantity = '1'
MATCHH = ['Match 3', 'Match 7', 'Match 8', 'Match 12', 'Match 16', 'Match 20', 'Match 24', 'Match 27', 'Match 31', 'Match 32',
          'Match 36', 'Match 37', 'Match 38', 'Match 21', 'Match 43', 'Match 44', 'Match 46', 'Match 49', 'Match 50', 'Match 51']
Category = ['Category 3']
TICKETS_AVAILABLE = []

EVENTS_TRIGGERED = []

MATCH = [
    {'match': 'Match 21', 'tickets': 1, 'category': 'Category 1'}


]


def Get_Proxy(sess=False):
    global PROXIES
    if len(PROXIES) > 0:
        entry = random.choice(PROXIES)
        pp = entry['username']+":"+entry['password'] + \
            "@"+entry['host']+":"+entry['port']
        proxyDict = {
            "http": 'http://' + pp,
            "https": 'https://' + pp
        }
        # proxyDict = {
        #                "http"  : pp,
        #                "https"  : pp
        #            }

    else:
        proxyDict = {
            "http": '127.0.0.1:8888',
            "https": '127.0.0.1:8888'
        }

        # proxyDict = {
        #    "http": 'http://168.119.153.224:3128',
        #    "https": 'https://168.119.153.224:3128'
        # }
    return proxyDict


def Log(LogText):
    global LOG_ROWS
    ts = datetime.now()

    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()
    cursor.execute(
        "insert into Logs (log_time,log_text) values(%s,%s)", (ts, LogText))
    connection.commit()
    cursor.close()
    connection.close()


def ImageCaptcha(img_base64):
    url = "http://2captcha.com/in.php"
    image_data = {'key': 'b90e3677f1b18437893267889dd982c6',
                  'body': img_base64, 'method': 'base64'}
    s = requests.session()
    resp = s.post(url, image_data)
    captcha_id = resp.text[3:]

    if resp.text[0:2] != 'OK':
        quit('Error. Captcha is not received')
    captcha_id = resp.text[3:]
    print("captcha_id :", captcha_id)

    fetch_url = "http://2captcha.com/res.php?key=b90e3677f1b18437893267889dd982c6&action=get&id="+captcha_id
    for i in range(1, 120):
        time.sleep(5)  # wait 5 sec.
        resp = requests.get(fetch_url)
        if resp.text[0:2] == 'OK':
            break
    print('Google response token: ', resp.text[3:])
    global value
    value = resp.text[3:]
    return value


def queueManager(prx):
    global Queue_Token
    global Queue_Token_Available
    global Queue_Available
    s1 = requests.session()
    headers1 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive'
    }
    r1 = s1.get("https://euro2020-sales.tickets.uefa.com",
                headers=headers1, verify=False, allow_redirects=True, proxies=prx)
    ss1 = r1.text
    page_Title = ''
    try:
        page_Title = ss1.split('<title>')[1].split('</title>')[0]
        page_Title = page_Title.strip()
    except:
        pass

    if(page_Title == "Waiting Room"):

        Queue_Available = True
        Log('Queue Available')
        r = s.get(
            'https://access-ticketshop.uefa.com/pkpcontroller/captcha.png', stream=True)
        path = './images'
        image_random_number = randint(100000, 999999)
        image_random_number = str(image_random_number)

        with open('img'+image_random_number+'.png', 'wb') as out_file:
            shutil.copyfileobj(r.raw, out_file)
        enc = '1'
        with open("img"+image_random_number+".png", "rb") as image_file:
            enc = base64.b64encode(image_file.read())
        captcha_code = ImageCaptcha(enc)

        headers2 = {
            'Accept': '*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
            'Referrer': 'https://access-ticketshop.uefa.com/pkpcontroller/wp/euro2020/index_en.html?queue=q-euro-2020',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive'
        }

        r2 = s1.get("https://access-ticketshop.uefa.com/pkpcontroller/servlet.do?CAPTCHA=" +
                    captcha_code, headers=headers2, allow_redirects=True, verify=False, proxies=prx)

        ss2 = r2.text
        Can_Enter = 'No'

        WRT = ss2.split('"token": ')[1].split(',')[0].replace('"', '')
        WRT = WRT.strip()

        CNT = ss2.split('"canEnter":')[1].split(',')[0].replace('"', '')
        CNT = CNT.strip()

        waiting_time = ss2.split('"waitingTime":')[1].split(',')[
            0].replace('"', '')
        waiting_time = waiting_time.strip()
        waiting_time = int(waiting_time)

        admission_token = 'p'
        try:
            admission_token = ss2.split('"admissionToken":')[
                1].split(',')[0].replace('"', '')
            admission_token = admission_token.strip()
        except:
            pass

        if(CNT == 'false' and waiting_time > 0):
            Can_Enter = 'No'
        elif('p1pkpcontroller' in admission_token and waiting_time == 0 and CNT == 'true'):
            Can_Enter = 'Yes'
        elif('p1pkpcontroller' not in admission_token and waiting_time == 0 and CNT == 'true'):
            Can_Enter = 'Partially'
        if(waiting_time > 50):
            time.sleep(30)

        if (Can_Enter == 'Partially'):
            headers2 = {
                'Accept': '*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
                'Referrer': 'https://access-ticketshop.uefa.com/pkpcontroller/wp/euro2020/index_en.html?queue=q-euro-2020',
                'Upgrade-Insecure-Requests': '1',
                'Connection': 'keep-alive'
            }

            r2 = s1.get("https://access-ticketshop.uefa.com/pkpcontroller/servlet.do?GEN_AT=true&WRT=" +
                        WRT, headers=headers2, allow_redirects=True, verify=False, proxies=prx)
            Queue_Token = WRT
            Queue_Token_Available = True
            Queue_Available = False
            Log('Queue Token - '+WRT)

        while(Can_Enter == 'No'):
            headers2 = {
                'Accept': '*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.8',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
                'Referrer': 'https://access-ticketshop.uefa.com/pkpcontroller/wp/euro2020/index_en.html?queue=q-euro-2020',
                'Upgrade-Insecure-Requests': '1',
                'Connection': 'keep-alive'
            }

            r2 = s1.get("https://access-ticketshop.uefa.com/pkpcontroller/servlet.do?WRT=" +
                        WRT, headers=headers2, allow_redirects=True, verify=False, proxies=prx)
            ss2 = r2.text
            WRT = ss2.split('"token": ')[1].split(',')[0].replace('"', '')
            WRT = WRT.strip()

            CNT = ss2.split('"canEnter":')[1].split(',')[0].replace('"', '')
            CNT = CNT.strip()

            waiting_time = ss2.split('"waitingTime":')[1].split(',')[
                0].replace('"', '')
            waiting_time = waiting_time.strip()
            waiting_time = int(waiting_time)

            admission_token = 'p'
            try:
                admission_token = ss2.split('"admissionToken":')[
                    1].split(',')[0].replace('"', '')
                admission_token = admission_token.strip()
            except:
                pass

            if(CNT == 'false' and waiting_time > 0):
                Can_Enter = 'No'
            elif('p1pkpcontroller' in admission_token and waiting_time == 0 and CNT == 'true'):
                Can_Enter = 'Yes'
            elif('p1pkpcontroller' not in admission_token and waiting_time == 0 and CNT == 'true'):
                Can_Enter = 'Partially'

            if(waiting_time > 50):
                time.sleep(30)

            if (Can_Enter == 'Partially'):
                headers2 = {
                    'Accept': '*',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.8',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
                    'Referrer': 'https://access-ticketshop.uefa.com/pkpcontroller/wp/euro2020/index_en.html?queue=q-euro-2020',
                    'Upgrade-Insecure-Requests': '1',
                    'Connection': 'keep-alive'
                }

                r2 = s1.get("https://access-ticketshop.uefa.com/pkpcontroller/servlet.do?GEN_AT=true&WRT=" +
                            WRT, headers=headers2, allow_redirects=True, verify=False, proxies=prx)
                Queue_Token = WRT
                Queue_Token_Available = True
                Queue_Available = False
                Log('Queue Token - '+WRT)

    else:
        Queue_Available = False
        Queue_Token_Available = True
        Log('Queue Not Available')


def TicketsMonitor(prx):

    global TICKETS_AVAILABLE
    prx = {
        'http': 'http://lum-customer-c_6220a918-zone-ticket-ip-154.30.246.214:15r24zborbf0@zproxy.lum-superproxy.io:22225',
        'https': 'lum-customer-c_6220a918-zone-ticket-ip-154.30.246.214:15r24zborbf0@zproxy.lum-superproxy.io:22225'
    }
    s = requests.Session()
    headers1 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive'
    }
    r1 = requests.get("https://euro2020-sales.tickets.uefa.com",
                      headers=headers1, verify=False, proxies=prx)
    ss1 = r1.text
    souper = BeautifulSoup(ss1, "lxml")
    saml = souper.find('input', attrs={'name': 'SAMLRequest'})
    Saml_Request = saml['value']
    Log("SAML GET")
    headers4 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    data_1 = {'SAMLRequest': Saml_Request}

    r4 = s.post("https://fidm.eu1.gigya.com/saml/v2.0/3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV/idp/sso?locale=en",
                headers=headers4, data=data_1, verify=False, proxies=prx)

    saml_context = r4.url.split('samlContext=')[1].split('&spName')[0].strip()

    headers5 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idpassets.uefa.com/',
        'Connection': 'keep-alive'
    }

    r5 = s.get("https://idp.uefa.com/accounts.webSdkBootstrap?apiKey=3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV&pageURL=https%3A%2F%2Fidpassets.uefa.com%2Fsaml%2Fticket-proxy.html%3Fmode%3Dlogin%26samlContext%3D8352704_70984189-c2d9-4956-8adf-11f5a42f6e5c%26spName%3Deuro2020%2520LMS%26locale%3Den&sdk=js_latest&sdkBuild=12119&format=json", headers=headers5, verify=False, proxies=prx)

    headers5 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idpassets.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    data_5 = {'loginID': 'nikhil@shabd.in',
              'password': 'Euro321!',
              'sessionExpiration': '-2',
              'targetEnv': 'jssdk',
              'include': 'profile,data,emails,subscriptions,preferences,',
              'includeUserInfo': True,
              'loginMode': 'standard',
              'lang': 'en',
              'APIKey': '3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV',
              'source': 'showScreenSet',
              'sdk': 'js_canary',
              'authMode': 'cookie',
              'pageURL': 'https://idpassets.uefa.com/saml/ticket-login.html?locale=en&mode=login&samlContext=8352704_c284b75c-dc63-47b0-8c35-f0585a984b6b&spName=euro2020%20LMS',
              'sdkBuild': '12088',
              'format': 'json'
              }
    r5 = s.post("https://idp.uefa.com/accounts.login",
                headers=headers5, data=data_5, verify=False, proxies=prx)

    ss5 = r5.text

    login_token = ss5.split('"login_token": ')[
        1].split('}')[0].replace('"', '')
    login_token = login_token.strip()

    headers6 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idpassets.uefa.com/',
        'Connection': 'keep-alive'
    }

    r6 = s.get("https://idp.uefa.com/saml/v2.0/3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV/idp/sso/continue?samlContext=" +
               saml_context+"&loginToken="+login_token, headers=headers6, verify=False, proxies=prx)
    ss6 = r6.text

    souper = BeautifulSoup(ss6, "lxml")

    saml = souper.find('input', attrs={'name': 'SAMLResponse'})
    Saml_Response = saml['value']

    data_1 = {'SAMLResponse': Saml_Response}

    headers7 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idp.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }
    r7 = s.post("https://euro2020-sales.tickets.uefa.com/api/1/sso/gigya/login",
                headers=headers7, data=data_1, verify=False, proxies=prx)

    headers8 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/api/1/sso/gigya/login',

        'Connection': 'keep-alive'
    }
    r8 = s.get("https://euro2020-sales.tickets.uefa.com/secured/content",
               headers=headers8, verify=False, proxies=prx)

    ss8 = r8.text

    api_key = ss8.split('apiKey:')[1].split(',')[0].replace('"', '')

    api_key = api_key.strip()

    csrf_tkn = ss8.split('csrfToken":')[1].split('}')[
        0].replace('"', '').strip()
    while True:
        headers8_1 = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'https://euro2020-sales.tickets.uefa.com/secured/content',
            'X-API-Key': api_key,
            'X-CSRF-Token': csrf_tkn,
            'X-Secutix-Host': 'euro2020-sales.tickets.uefa.com',
            'Connection': 'keep-alive'
        }
        r8_1 = s.get("https://euro2020-sales.tickets.uefa.com/tnwr/v1/catalog?maxPerformances=50&maxTimeslots=50&maxPerformanceDays=3&maxTimeslotDays=3&includeMetadata=true",
                     headers=headers8_1, verify=False, proxies=prx)
        r8_1_data = r8_1.text
        json_object = json.loads(r8_1_data)
        tickets_array = json_object['sections'][0]['clusters'][0]['items']
        match_id = ''
        match_number = ''

        for i in tickets_array:
            match_number = i['product']['performances'][0]['roundName']
            if(match_number in MATCHH):
                match_id = i['product']['performances'][0]['performanceId']
                if match_number not in EVENTS_TRIGGERED:
                    TICKETS_AVAILABLE.append(match_number)
                    EVENTS_TRIGGERED.append(match_number)
                    Log("Tickets Available for - "+match_number)

        time.sleep(45)


def EuroCheckout(prx, user_object, matchnumber, category_provided):
    global TICKETS_AVAILABLE
    Saml_Request = ''
    email = user_object['email']
    password = user_object['password']
    global CARDS
    s = requests.session()
    while(Queue_Available == True):
        time.sleep(1)
        while(Queue_Token_Available == False):
            time.sleep(1)

    # prx = {
    #        "http": '127.0.0.1:8888',
    #        "https": '127.0.0.1:8888'
    #    }

    if(Queue_Available == False):

        headers1 = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive'
        }
        r1 = s.get("https://euro2020-sales.tickets.uefa.com",
                   headers=headers1, verify=False, allow_redirects=True, proxies=prx)
        ss1 = r1.text
        souper = BeautifulSoup(ss1, "lxml")
        saml = souper.find('input', attrs={'name': 'SAMLRequest'})
        Saml_Request = saml['value']
    else:

        headers2 = {
            'Accept': '*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
            'Referrer': 'https://access-ticketshop.uefa.com/pkpcontroller/wp/euro2020/index_en.html?queue=q-euro-2020',
                        'Upgrade-Insecure-Requests': '1',
                        'Connection': 'keep-alive'
        }

        r2 = s.get("https://access-ticketshop.uefa.com/pkpcontroller/servlet.do?GEN_AT=true&WRT=" +
                   Queue_Token, headers=headers2, verify=False, proxies=prx)
        headers3 = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'https://access-ticketshop.uefa.com/',
            'Connection': 'keep-alive'
        }
        r3 = s.get("https://euro2020-sales.tickets.uefa.com/",
                   headers=headers1, verify=False, proxies=prx)
        ss3 = r3.text
        souper = BeautifulSoup(ss3, "lxml")
        saml = souper.find('input', attrs={'name': 'SAMLRequest'})
        Saml_Request = saml['value']

    headers4 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    data_1 = {'SAMLRequest': Saml_Request}

    r4 = s.post("https://fidm.eu1.gigya.com/saml/v2.0/3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV/idp/sso?locale=en",
                headers=headers4, allow_redirects=True, data=data_1, verify=False, proxies=prx)
    #tt =pytesseract.pytesseract.image_to_string(Image.open(image_path))
    # text = pytesseract.image_to_string(Image.open(image_path))  # We'll use Pillow's Image class to open the image and pytesseract to detect the string in the image
    # return text
    #img = Image.open(image_path)
    #pytesseract.tesseract_cmd = path_to_tesseract
    #text = pytesseract.image_to_string(img)
    # print(text[:-1])

    saml_context = r4.url.split('samlContext=')[1].split('&spName')[0].strip()

    headers5 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idpassets.uefa.com/',
        'Connection': 'keep-alive'
    }

    r5 = s.get("https://idp.uefa.com/accounts.webSdkBootstrap?apiKey=3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV&pageURL=https%3A%2F%2Fidpassets.uefa.com%2Fsaml%2Fticket-proxy.html%3Fmode%3Dlogin%26samlContext%3D8352704_70984189-c2d9-4956-8adf-11f5a42f6e5c%26spName%3Deuro2020%2520LMS%26locale%3Den&sdk=js_latest&sdkBuild=12119&format=json", headers=headers5, allow_redirects=True, verify=False, proxies=prx)

    headers5 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idpassets.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    data_5 = {'loginID': email,
              'password': password,
              'sessionExpiration': '-2',
              'targetEnv': 'jssdk',
              'include': 'profile,data,emails,subscriptions,preferences,',
              'includeUserInfo': True,
              'loginMode': 'standard',
              'lang': 'en',
              'APIKey': '3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV',
              'source': 'showScreenSet',
              'sdk': 'js_canary',
              'authMode': 'cookie',
              'pageURL': 'https://idpassets.uefa.com/saml/ticket-login.html?locale=en&mode=login&samlContext=8352704_c284b75c-dc63-47b0-8c35-f0585a984b6b&spName=euro2020%20LMS',
              'sdkBuild': '12088',
              'format': 'json'
              }
    r5 = s.post("https://idp.uefa.com/accounts.login", headers=headers5,
                data=data_5, allow_redirects=True, verify=False, proxies=prx)

    ss5 = r5.text

    login_token = ss5.split('"login_token": ')[
        1].split('}')[0].replace('"', '')
    login_token = login_token.strip()

    headers6 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idpassets.uefa.com/',
        'Connection': 'keep-alive'
    }

    r6 = s.get("https://idp.uefa.com/saml/v2.0/3_WhoQ5kSze6W6uz1oBpBfDNQkMRYi8y2RC32TGpY6XKRxlOeTTLjY-qIrnw4hJaLV/idp/sso/continue?samlContext=" +
               saml_context+"&loginToken="+login_token, headers=headers6, allow_redirects=True, verify=False, proxies=prx)
    ss6 = r6.text

    souper = BeautifulSoup(ss6, "lxml")

    saml = souper.find('input', attrs={'name': 'SAMLResponse'})
    Saml_Response = saml['value']

    data_1 = {'SAMLResponse': Saml_Response}

    headers7 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://idp.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }
    r7 = s.post("https://euro2020-sales.tickets.uefa.com/api/1/sso/gigya/login",
                headers=headers7, data=data_1, allow_redirects=True, verify=False, proxies=prx)

    headers8 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/api/1/sso/gigya/login',

        'Connection': 'keep-alive'
    }
    r8 = s.get("https://euro2020-sales.tickets.uefa.com/secured/content",
               headers=headers8, allow_redirects=True, verify=False, proxies=prx)

    ss8 = r8.text

    Log('Login Successful for '+email)

    api_key = ss8.split('apiKey:')[1].split(',')[0].replace('"', '')

    api_key = api_key.strip()

    csrf_tkn = ss8.split('csrfToken":')[1].split('}')[
        0].replace('"', '').strip()

    headers8_1 = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/secured/content',
        'X-API-Key': api_key,
        'X-CSRF-Token': csrf_tkn,
        'X-Secutix-Host': 'euro2020-sales.tickets.uefa.com',
        'Connection': 'keep-alive'
    }
    r8_1 = s.get("https://euro2020-sales.tickets.uefa.com/tnwr/v1/catalog?maxPerformances=50&maxTimeslots=50&maxPerformanceDays=3&maxTimeslotDays=3&includeMetadata=true",
                 headers=headers8_1, allow_redirects=True, verify=False, proxies=prx)
    r8_1_data = r8_1.text
    json_object = json.loads(r8_1_data)
    tickets_array = json_object['sections'][0]['clusters'][0]['items']
    match_id = ''
    match_number = ''

    for i in tickets_array:
        match_number = i['product']['performances'][0]['roundName']
        if(match_number in matchnumber):
            match_id = i['product']['performances'][0]['performanceId']

    match_id = str(match_id)

    #match_id = str(matchid)
    headers9 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/secured/content',

        'Connection': 'keep-alive'
    }
    r9 = s.get("https://euro2020-sales.tickets.uefa.com/secured/selection/event/seat?perfId="+match_id +
               "&ot=0&gtmStepTracking=true", headers=headers9, allow_redirects=True, verify=False, proxies=prx)
    ss9 = r9.text

    souper = BeautifulSoup(ss9, "lxml")

    Categories_Rows = souper.find_all(
        'tr', attrs={'data-conditionalrateid': '__551183968'})
    category_id = ''
    for ct in Categories_Rows:
        category = ct.find('h3')
        category = category.text
        category = category.strip()
        if category in category_provided:
            cat_id = ct['class'][0]
            category_id = cat_id.replace('v2-seatcat_', '').replace("'", "")

    Log("Tickets Available For User - "+email +
        " Match -  "+matchnumber+" Category - "+category)
    r = s.get('https://euro2020-sales.tickets.uefa.com/captcha', stream=True)
    path = './images'
    image_random_number = randint(100000, 999999)
    image_random_number = str(image_random_number)

    with open('img'+image_random_number+'.png', 'wb') as out_file:
        shutil.copyfileobj(r.raw, out_file)
    enc = '1'
    with open("img"+image_random_number+".png", "rb") as image_file:
        enc = base64.b64encode(image_file.read())
    captcha_code2 = ImageCaptcha(enc)

    headers10 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/secure/selection/event/seat/performance/552003080/lang/en',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    data_10 = {
        'error': 'Uncaught ReferenceError: grecaptcha is not defined',
        'file': 'https://euro2020-sales.tickets.uefa.com/resources/stx2js-all.js (Line 1764 / Column 28 )',
        'href': 'https://euro2020-sales.tickets.uefa.com/secure/selection/event/seat/performance/552003080/lang/en',
        'stack': 'ReferenceError: grecaptcha is not defined at https://euro2020-sales.tickets.uefa.com/resources/stx2js-all.js:1764:28',
        'platform': 'Win32',
        'viewport': 'x: 0, y: -524, width: 1519.2000732421875, height: 1939.800048828125, top: -524, right: 1519.2000732421875, bottom: 1415.800048828125, left: 0, toJSON: function toJSON() { [native code] }',
        'clicks': 'x:841, y:1032, time:265248, element: #captcha_response_field x:969, y:998, time:261447, element: #book[1] x:0, y:524, time:259827, element: #eventFormData2.quantity x:624, y:857, time:257173, element: #eventFormData2.quantity'
    }

    r10 = s.post("https://euro2020-sales.tickets.uefa.com/ajax/error/javascript",
                 data=data_10, headers=headers10, verify=False, allow_redirects=True, proxies=prx)

    headers11 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/secure/selection/event/seat/performance/552003080/lang/en',
        'Content-Type': 'application/json',
        'Connection': 'keep-alive'
    }

    # data_11 = {
    #           'captcha':captcha_code2,
    #           'performanceId':match_id,
    #           'tourId':None,
    #           'eventFormData':[{'advantageId':None, 'audienceSubCategory':'551183968', 'priceLevelId':None,'quantity':ticket_quantity,'seatCategory':'569860897'},
    #                            {'advantageId':None, 'audienceSubCategory':'551183968', 'priceLevelId':None,'seatCategory':'569860891'},
    #                            {'advantageId':None, 'audienceSubCategory':'551183968', 'priceLevelId':None,'seatCategory':'569860889'}
    #                            ],
    #           'preferredAreas':{}

    #           }
    data_11 = {
        'captcha': captcha_code2,
        'performanceId': match_id,
        'tourId': None,
        'eventFormData': [{'advantageId': None, 'audienceSubCategory': '551183968', 'priceLevelId': None, 'quantity': ticket_quantity, 'seatCategory': category_id}

                          ],
        'preferredAreas': {}

    }
    r11 = s.post("https://euro2020-sales.tickets.uefa.com/ajax/selection/event/submit",
                 json=data_11, headers=headers11, verify=False, allow_redirects=True, proxies=prx)

    headers12 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/secure/selection/event/seat/performance/552003080/lang/en',
        'Connection': 'keep-alive'
    }
    r12 = s.get("https://euro2020-sales.tickets.uefa.com/cart/reservation/0",
                headers=headers12, allow_redirects=True, verify=False, proxies=prx)

    Log("Cart Added For User - "+email + " Match -  " +
        matchnumber+" Category - "+category)

    headers13 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/cart/reservation/0',
        'Connection': 'keep-alive'
    }
    r13 = s.get("https://euro2020-sales.tickets.uefa.com/checkout/redirect",
                headers=headers13, allow_redirects=True, verify=False, proxies=prx)

    ss13 = r13.text

    movement_id = ss13.split(
        'data-movement-id="')[1].split('>')[0].replace('"', '')
    movement_id = movement_id.strip()

    souper = BeautifulSoup(ss13, "lxml")

    csrf_token = souper.find('input', attrs={'name': '_csrf'})
    csrf_token = csrf_token['value']

    #csrf_token = '426f8845-adb4-4d48-bc87-33808d032da2'
    #movement_id = '101623486266'

    headers14 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/checkout/beneficiaries',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    benef_dat = []

    benficiery_Data = {
        'ticketBeneficiaryFormModels[0].id': movement_id,
        'ticketBeneficiaryFormModels[0].support': '',
        'ticketBeneficiaryFormModels[0].fileName': '',
        'ticketBeneficiaryFormModels[0].questionnaireId': '-1',
        'ticketBeneficiaryFormModels[0].movementId': movement_id,
        'ticketBeneficiaryFormModels[0].fileId': '',
        'ticketBeneficiaryFormModels[0].hospitalityProductType': '',
        'ticketBeneficiaryFormModels[0].zipCode': '',
        'ticketBeneficiaryFormModels[0].questionnaires[0].id': '-1',
        'ticketBeneficiaryFormModels[0].firstName': 'Amit',
        'ticketBeneficiaryFormModels[0].lastName': 'Misra',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[0].code': 'QU_EXB_BD',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[0].answerType': 'DATE',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[0].day': '11',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[0].month': '10',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[0].year': '1988',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[1].code': 'QU_EXB_NA',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[1].answerType': 'LIST_SINGLE',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[2].code': 'QU_EXB_BP',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[2].answerType': 'TEXT',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[2].answer': '',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[3].code': 'QU_EXB_BR',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[3].answerType': 'TEXT',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[4].code': 'QU_EXB_ID',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[4].answerType': 'TEXT',
        'ticketBeneficiaryFormModels[0].questionnaires[0].questions[4].answer': 'PWTIO7865A',
        'ticketBeneficiaryFormModels[0].containerIdentifier': '',
        '_csrf': csrf_token
    }
    benef_dat.append(benficiery_Data)

    r14 = s.post("https://euro2020-sales.tickets.uefa.com/checkout/beneficiaries",
                 data=benficiery_Data, headers=headers14, allow_redirects=True, verify=False, proxies=prx)

    headers15 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/checkout/beneficiaries',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
        'sec-ch-ua-mobile': '?0',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1'
    }
    r15 = s.get("https://euro2020-sales.tickets.uefa.com/checkout/deliveryModes",
                headers=headers15, allow_redirects=True, verify=False, proxies=prx)

    ss15 = r15.text

    address_id = ss15.split('{ addressId	  		: ')[
        1].split(',')[0].replace('"', '')

    address_id = address_id.strip()

    address_id = address_id.replace("'", "")

    shipment_contact_number = ss15.split('shipmentContactNumber : ')[
        1].split(',')[0].replace('"', '')

    shipment_contact_number = shipment_contact_number.strip()

    shipment_contact_number = shipment_contact_number.replace("'", "")

    #address_id = '101614554713'
    #shipment_contact_number = '6764628'

    headers16 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/checkout/deliveryModes',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    delivery_Data = {
        'isFinalizeRequest': '',
        'fileId': '',
        'shipmentModeHackEnabled': 'false',
        'shipmentModeType': 'BY_MAIL',
        'shipmentModeId': '629375642',
        'contactAddressId': address_id,
        'shipmentContactNumber[629375642]': shipment_contact_number,
        'shipmentContactNumber[556551614]': '',
        '_csrf': csrf_token
    }

    r16 = s.post("https://euro2020-sales.tickets.uefa.com/checkout/deliveryModes",
                 data=delivery_Data, headers=headers16, allow_redirects=True, verify=False, proxies=prx)

    ss16 = r16.text

    shipmentId = ss16.split('shipmentId":')[1].split(',')[0]
    shipmentId = shipmentId.strip()

    souper = BeautifulSoup(ss16, "lxml")

    shipmentAddressId = souper.find(
        'input', attrs={'name': 'ticketShipment.shippingAddressId'})
    shipmentAddressId = shipmentAddressId['value']

    billingContactNumber = ss16.split('shipmentContactNumber : ')[
        1].split(',')[0].replace('"', '')
    billingContactNumber = billingContactNumber.strip()
    billingContactNumber = billingContactNumber.replace("'", "")

    paymentMethodId = souper.find('input', attrs={'name': 'paymentMethodId'})
    paymentMethodId = paymentMethodId['value']

    localCurrencyAmount = souper.find(
        'td', attrs={'class': 'stx_tfooter reservation_amount'})
    localCurrencyAmount = localCurrencyAmount['data-amount']
    if(len(localCurrencyAmount) == 5):
        localCurrencyAmount = localCurrencyAmount[:2]
    if(len(localCurrencyAmount) == 6):
        localCurrencyAmount = localCurrencyAmount[:3]
    #localCurrencyAmount = localCurrencyAmount.replace('0','')

    localCurrencyAmount = localCurrencyAmount + " GBP"

    #shipmentId = '629375642'
    #shipmentAddressId = '542828320'
    #billingContactNumber = '3148618'
    #paymentMethodId = '559783309'
    #localCurrencyAmount = '103 GBP'

    headers17 = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/checkout/summary',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    validate_Data = {
        'isFinalizeRequest': 'false',
        'ticketShipment.shipmentModeId': shipmentId,
        'ticketShipment.shipmentModeType': 'BY_MAIL',
        'ticketShipment.shippingAddressId': shipmentAddressId,
        'billingAddressId': shipmentAddressId,
        'billingContactNumber': billingContactNumber,
        'paymentMethodId': paymentMethodId,
        'conditionsAccepted': 'true',
        '_conditionsAccepted': 'on',
        'cancelInsuranceOperations': '',
        'localCurrencyAmount': localCurrencyAmount,
        '_csrf': csrf_token
    }

    r17 = s.post("https://euro2020-sales.tickets.uefa.com/checkout/validateOrder",
                 data=validate_Data, headers=headers17, allow_redirects=True, verify=False, proxies=prx)

    ss17 = r17.text
    souper = BeautifulSoup(ss17, "lxml")

    ALIAS_REGISTRATION_REQUEST_ID = souper.find(
        'input', attrs={'name': 'ALIAS_REGISTRATION_REQUEST_ID'})
    ALIAS_REGISTRATION_REQUEST_ID = ALIAS_REGISTRATION_REQUEST_ID['value']

    ALIAS_REGISTRATION_URL = souper.find(
        'input', attrs={'name': 'ALIAS_REGISTRATION_URL'})
    ALIAS_REGISTRATION_URL = ALIAS_REGISTRATION_URL['value']

    Log("Data Validated For User - "+email +
        " Match -  "+matchnumber+" Category - "+category)

    headers18 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
        'Referer': 'https://euro2020-sales.tickets.uefa.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'keep-alive'
    }

    cards = random.choice(CARDS)

    c_number = cards['card_number']
    c_holder = cards['card_holder']
    c_cvv = cards['cvv']
    c_expm = cards['expm']
    c_expy = cards['expy']
    Log("Cards get for  - "+email + " Match -  "+matchnumber+" card - "+c_number)

    # card_Data = {
    #                'ALIAS_REGISTRATION_REQUEST_IDlizeRequest': ALIAS_REGISTRATION_REQUEST_ID,
    #                'ALIAS_REGISTRATION_URL': ALIAS_REGISTRATION_URL,
    #                'CardNumber': c_number,
    #                'ExpMonth':c_expm,
    #                'ExpYear': c_expy,
    #                'HolderName': c_holder,
    #                'VerificationCode': c_cvv,
    #                'FromAjax': 'true'
    #            }

    #r18 = s.post(ALIAS_REGISTRATION_URL,data=card_Data,headers=headers18,verify=False,allow_redirects=True,proxies=prx)

    #ss18 = r18.text

    #RedirectUrl = ss18.split('{"RedirectUrl":')[1].split('}')[0].replace('"','')
    #RedirectUrl = RedirectUrl.strip()

    # headers19 = {
    #            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    #            'Accept-Encoding': 'gzip, deflate, br',
    #            'Accept-Language': 'en-US,en;q=0.8',
    #            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
    #            'Referer': 'https://euro2020-sales.tickets.uefa.com/',
    #            'Connection': 'keep-alive'
    #            }
    #r19 = s.get(RedirectUrl,headers=headers19,verify=False,proxies=prx)

    #ss19 = r19.text

    #ref_url = r19.url.strip()
    #souper = BeautifulSoup(ss19, "lxml")

    #TermUrl = souper.find('input', attrs={'name':'TermUrl'})
    #TermUrl = TermUrl['value']

    #MD = souper.find('input', attrs={'name':'MD'})
    #MD = MD['value']

    #PaReq = souper.find('input', attrs={'name':'PaReq'})
    #PaReq = PaReq['value']

    #action = ss19.split('form action="')[1].split('" method')[0].replace('"','').strip()

    # headers20 = {
    #            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    #            'Accept-Encoding': 'gzip, deflate, br',
    #            'Accept-Language': 'en-US,en;q=0.8',
    #            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
    #            'Referer': 'https://www.saferpay.com/',
    #            'Content-Type': 'application/x-www-form-urlencoded',
    #            'X-Requested-With': 'XMLHttpRequest',
    #            'Connection': 'keep-alive'
    #            }

    # data_20 = {
    #                'MD': MD,
    #                'PaReq': PaReq,
    #                'TermUrl': TermUrl
    #            }
    #r20 = s.post(action,data=data_20,headers=headers20,verify=False,proxies=prx)
    #ss20 = r20.text

    #souper = BeautifulSoup(ss19, "lxml")

    #PaRes = souper.find('input', attrs={'name':'PaRes'})
    #PaRes = PaRes['PaRes']

    #Redi_Url = souper.find('form', attrs={'name':'downloadForm'})
    #Redi_Url = Redi_Url['action']

    # headers21 = {
    #            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    #            'Accept-Encoding': 'gzip, deflate, br',
    #            'Accept-Language': 'en-US,en;q=0.8',
    #            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
    #            'Referer': 'https://cap.attempts.securecode.com/',
    #            'Content-Type': 'application/x-www-form-urlencoded',
    #            'X-Requested-With': 'XMLHttpRequest',
    #            'Connection': 'keep-alive'
    #            }

    # data_21 = {
    #                'PaRes': PaRes,
    #                'PaReq': PaReq,
    #                'MD': MD,
    #                'ABSlog':'GBP',
    #                'deviceDNA':'',
    #                'executionTime':'',
    #                'dnaError':'',
    #                'mesc':'',
    #                'mescIterationCount':'0',
    #                'desc':'',
    #                'isDNADone':'false',
    #                'arcotFlashCookie':''
    #            }
    #r21 = s.post(Redi_Url,data=data_21,headers=headers21,verify=False,proxies=prx)
    #ss21 = r21.text
    #Conf_url = ss21.split('form action="')[1].split('>')[0].replace('"','')
    #Conf_url = "www.saferpay.com"+Conf_url

    # headers22 = {
    #            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    #            'Accept-Encoding': 'gzip, deflate, br',
    #            'Accept-Language': 'en-US,en;q=0.8',
    #            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
    #            'Referer': Redi_Url,
    #            'Connection': 'keep-alive'
    #            }

    #r22 = s.get(Conf_url,headers=headers22,verify=False,proxies=prx)
    #ss22 = r22.text
    #Log("Successful Checkout for  - "+email+ " Match -  "+matchnumber+" Category - "+category)

    #ss = 1


def main():
    global StopBot
    global TICKETS_AVAILABLE
    if StopBot == False:
        # Log('Started')
        connection = mysql.connector.connect(**config)
        connection.autocommit = True
        cursor = connection.cursor()

        cursor.execute("SELECT  * from Settings")
        sets = cursor.fetchall()
        stop_bot = ''
        if len(sets) > 0:
            for row in sets:
                stop_bot = row[1]
        if(stop_bot == 'Stop'):
            StopBot = True

        cursor.execute("SELECT  * from Users where status = 'active'")
        usrs = cursor.fetchall()
        if len(usrs) > 0:
            for row in usrs:
                usr = {
                    'email': row[1],
                    'password': row[2],
                    'status': row[3]
                }
                USERS.append(usr)

        cursor.execute("SELECT  * from Proxies")
        prxs = cursor.fetchall()
        if len(prxs) > 0:
            for row in prxs:
                pxr = {
                    'host': row[1],
                    'port': row[2],
                    'username': row[3],
                    'password': row[4]
                }
                PROXIES.append(pxr)

        cursor.execute("SELECT  * from Cards")
        cds = cursor.fetchall()
        if len(cds) > 0:
            for row in cds:
                card = {
                    'card_holder': row[1],
                    'card_number': row[2],
                    'cvv': row[3],
                    'expm': row[4],
                    'expy': row[5]
                }
                CARDS.append(card)

        uss = random.choice(USERS)
        proxy = Get_Proxy()
        #proxy = None
        #cards = random.choice(CARDS)

        _thread.start_new_thread(TicketsMonitor, (proxy,))

        while True:

            if(len(TICKETS_AVAILABLE) > 0):
                time.sleep(1)
                proxy = Get_Proxy()
                #proxy = None
                _thread.start_new_thread(queueManager, (proxy,))
                for mtch in TICKETS_AVAILABLE:
                    uss = random.choice(USERS)

                    for m in MATCH:
                        matchno = m['match']
                        if matchno in mtch:
                            tickets = m['tickets']
                            Category = m['category']
                            tickets = int(tickets)
                            for i in range(tickets):
                                _thread.start_new_thread(
                                    EuroCheckout, (proxy, uss, matchno, Category,))
                TICKETS_AVAILABLE = []
        StopBot = True

    # EuroCheckout()


if __name__ == '__main__':
    main()
