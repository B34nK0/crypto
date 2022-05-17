import datetime
import json
import urllib
import hmac
import time
from urllib.request import urlopen
from urllib import parse
from dateutil import tz
import secrets
import subprocess
import base64 # ??

def binance_signature(request,apiKey,apiSercrt):
    # 增加签名头部的ApiKey
    request.add_header('X-mbx-apikey',apiKey)
    # 解析query string
    full_url = request.get_full_url()
    parse_result = list(urllib.parse.urlparse(full_url))
    query_param = dict(parse.parse_qsl(parse_result[4]))
    # query string增加时间戳
    query_param['timestamp'] = int(round(time.time()*1000))
    # query string增加singnature
    param = urllib.parse.urlencode(query_param)
    signature = hmac.new(apiSercrt.encode(),param.encode(),digestmod='sha256').hexdigest()
    query_param['signature'] = signature
    # 更新query string
    parse_result[4] = urllib.parse.urlencode(query_param)
    request.full_url = parse.urlunparse(parse_result)
    return request

def huobi_signature(request,apiKey,apiSercrt):
    # 解析query string
    full_url = request.get_full_url()
    parse_result = list(urllib.parse.urlparse(full_url))
    query_param = dict(parse.parse_qsl(parse_result[4]))
    # 拼接查询字符串
    tz_sh = tz.gettz('Asia/Shanghai')
    timestamp = datetime.datetime.now(tz=tz_sh).strftime('%Y-%m-%dT%H:%M:%S')
    query_param['AccessKeyId'] = apiKey
    query_param['SignatureMethod'] = 'HmacSHA256'
    query_param['SignatureVersion'] = 2
    query_param['Timestamp'] = timestamp
    # 按ascii码进行排序
    query_param = dict(sorted(query_param.items()))
    # 进行URL编码
    url_value = urllib.parse.urlencode(query_param)
    # 签名字符串构建
    signature_str = request.get_method()+"\\n"+parse_result[1]+"\\n"+parse_result[2]+"\\n"+url_value
    # 进行签名
    signature = hmac.new(apiSercrt.encode(),signature_str.encode(),digestmod='sha256').hexdigest()
    # 添加签名
    query_param['Signature'] = signature
    # 更新query string
    parse_result[4] = urllib.parse.urlencode(query_param)
    request.full_url = parse.urlunparse(parse_result)
    return request

def deribit_signature(request,apiKey,apiSercrt):
    # 组合request信息为ResquestData
    req_method = request.method
    full_url = urllib.parse.urlparse(request.url)
    req_uri = full_url.path

    req_body = ""
    requestData = str.upper(req_method)+f"\n"+req_uri+f"\n"+req_body+f"\n"
    # 组合StringToSign
    timestamp = int(round(time.time()*1000))
    command_str = subprocess.Popen(f"cat /dev/urandom | tr -dc 'a-z0-9' | head -c8",stdout=subprocess.PIPE,shell=True).communicate()[0]
    nonce = command_str.decode("utf-8")
    stringToSign = str(timestamp) +f"\n" + nonce +f"\n" + requestData
    # 加密
    signature = hmac.new(apiSercrt.encode(),stringToSign.encode(),digestmod='sha256').hexdigest()
    # 更新header
    authorization = "deri-hmac-sha256 id="+apiKey+",ts="+str(timestamp)+",nonce="+nonce+",sig="+signature
    request.headers['Authorization'] = authorization
    return request

def mexc_signature(request,apiKey,apiSercrt):
    # 更新header
    request.add_header('X-MEXC-APIKEY',apiKey)
    request.add_header('Content-Type',"application/json")
    # 解析queryString
    full_url = request.get_full_url()
    parse_result = list(urllib.parse.urlparse(full_url))
    query_param = dict(parse.parse_qsl(parse_result[4]))
    url_value = urllib.parse.urlencode(query_param)
    # 加密
    signature = hmac.new(apiSercrt.encode(),url_value.encode(),digestmod='sha256').hexdigest()
    # 添加签名
    query_param['Signature'] = signature
    # 更新query string
    parse_result[4] = urllib.parse.urlencode(query_param)
    request.full_url = parse.urlunparse(parse_result)
    return request

def ftx_signature(request,apiKey,apiSercrt):
    # 获取timestamp
    ts = int(time.time() * 1000)
    # signature_payload
    signature_payload = str(ts) + request.get_method() + request.selector.split("?")[0]
    # 加密
    signature = hmac.new(apiSercrt.encode(),signature_payload.encode(),digestmod='sha256').hexdigest()
    # 添加header
    request.add_header('FTX-KEY',apiKey)
    request.add_header('FTX-SIGN',signature)
    request.add_header('FTX-TS',str(ts))
    return request

def coinbase_signature(request,apiKey,apiSercrt):
    return request

def namebase_signature(request,apiKey,apiSecret):
    # Basic认证
    str = ('%s:%s' % (apiKey,apiSecret))
    str = str.encode('utf-8')
    basestr = base64.b64encode(str)
    basestr = basestr.decode('utf-8')
    authorization = 'Basic '+basestr
    # 更新header
    request.add_header('Authorization',authorization)
    return request

def coinlist_signature(request,apiKey,apiSercrt):
    # integer seconds since the Unix Epoch in UTC
    ts = int(round(time.time() * 1000))
    # 解析query string
    full_url = request.get_full_url()
    parse_result = list(urllib.parse.urlparse(full_url))
    query_path = parse_result[2]
    # 加密
    signature_str = str(ts) + str.upper(request.get_method()) + query_path
    signature = hmac.new(signature_str.encode(),digestmod='sha256').hexdigest()
    # 更新header
    request.add_header('CL-ACCESS-KEY',apiKey)
    request.add_header('CL-ACCESS-SIG',signature)
    request.add_header('CL-ACCESS-TIMESTAMP',str(ts))
    return request

def tradestation_signature(request,apiKey,apiSercrt):
    auth_base_url = 'https://signin.tradestation.com/authorize'
    auth_param = {}
    auth_param['response_type'] = 'code'
    auth_param['client_id'] = apiKey
    auth_param['audience'] = 'https://api.tradestation.com'
    auth_param['redirect_uri'] = 'https://exampleclientapp/callback' # ??
    auth_param['scope'] = 'ReadAccount'
    auth_url_value = urllib.parse.urlencode(auth_param)
    auth_full_url = auth_base_url+"?"+auth_url_value
    auth_req = urllib.request.Request(auth_full_url, headers=request.headers)
    response = urllib.request.urlopen(auth_req)
    auth_result = list(urllib.parse.urlparse(response.headers['Location']))
    auth_query_param = dict(parse.parse_qsl(auth_result[4]))
    authorization = auth_query_param['code']
    # expire in 20mins
    request.add_header('Authorization',authorization)
    return request

def binance_api():
    base_url = 'https://api.binance.com'
    bnb_apikey = 'vmPUZE6mv9SD5VNHk4HlWFsOr6aKE2zvsw0MuIgwCIPy6utIco14y7Ju91duEh8A'
    bnb_secretkey = 'NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j'
    bnb_endpoint = '/api/v3/order'
    param = {}
    param['symbol'] = 'LTCBTC'
    param['side'] = 'BUY'
    param['type'] = 'LIMIT'
    param['timeInForce'] = 'GTC'
    param['quantity'] = '1'
    param['price'] = '0.1'
    param['recvWindow'] = '5000'
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+bnb_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = binance_signature(request,bnb_apikey,bnb_secretkey)
    print(req_after_sign.get_full_url())

def huobi_api():
    base_url = 'https://api.huobi.pro'
    huobi_apikey = 'vmPUZE6mv9SD5VNHk4HlWFsOr6aKE2zvsw0MuIgwCIPy6utIco14y7Ju91duEh8A'
    huobi_secretkey = 'NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j'
    huobi_endpoint = '/v1/order/orders'
    param = {}
    param['order-id'] = '1234567890'
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+huobi_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = huobi_signature(request,huobi_apikey,huobi_secretkey)
    print(req_after_sign.get_full_url())

def deribit_api():
    base_url = 'https://www.deribit.com'
    deribit_apikey = 'AMANDA'
    deribit_secretkey = 'AMANDASECRECT'
    deribit_endpoint = '/api/v2/private/get_account_summary'
    param = {}
    param['currency'] = 'BTC'
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+deribit_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = deribit_signature(request,deribit_apikey,deribit_secretkey)
    print(req_after_sign.get_full_url())

def mexc_api():
    base_url = 'https://api.mexc.com'
    mexc_apikey = 'mx0aBYs33eIilxBWC5'
    mexc_secretkey = '45d0b3c26f2644f19bfb98b07741b2f5'
    mexc_endpoint = '/api/v3/order'
    param = {}
    param['symbol'] = 'BTCUSDT'
    param['side'] = 'BUY'
    param['type'] = 'LIMIT'
    param['quantity'] = '1'
    param['price'] = '11'
    param['recvWindow'] = '5000'
    param['timestamp'] = '1644489390087'
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+mexc_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = mexc_signature(request,mexc_apikey,mexc_secretkey)
    print(req_after_sign.get_full_url())

def ftx_api():
    base_url = 'https://ftx.com/api'
    ftx_apikey = 'LR0RQT6bKjrUNh38eCw9jYC89VDAbRkCogAc_XAm'
    ftx_secretkey = 'T4lPid48QtjNxjLUFOcUZghD7CUJ7sTVsfuvQZF2'
    ftx_endpoint = '/markets'
    param = {}
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+ftx_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = ftx_signature(request,ftx_apikey,ftx_secretkey)
    print(req_after_sign.get_full_url())

def coinbase_api():
    base_url = 'https://ftx.com/api'
    ftx_apikey = 'LR0RQT6bKjrUNh38eCw9jYC89VDAbRkCogAc_XAm'
    ftx_secretkey = 'T4lPid48QtjNxjLUFOcUZghD7CUJ7sTVsfuvQZF2'
    ftx_endpoint = '/markets'
    param = {}
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+ftx_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = ftx_signature(request,ftx_apikey,ftx_secretkey)
    print(req_after_sign.get_full_url())

def namebase_api():
    base_url = 'https://www.namebase.io'
    namebase_apikey = '-----'
    namebase_secretkey = '-----'
    namebase_endpoint = '/api/v3/order'
    param = {}
    param['symbol'] = 'ETHBTC'
    param['timestamp'] = '-----'
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+namebase_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = namebase_signature(request,namebase_apikey,namebase_secretkey)
    print(req_after_sign.get_full_url())

def coinlist_api():
    base_url = 'https://trade-api.coinlist.co/v1'
    coinlist_apikey = '-----'
    coinlist_secretkey = '-----'
    coinlist_endpoint = '/orders'
    param = {}
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+coinlist_endpoint+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = coinlist_signature(request,coinlist_apikey,coinlist_secretkey)
    print(req_after_sign.get_full_url())

def tradestation_api():
    base_url = 'https://api.tradestation.com/v3'
    tradestation_apikey = '-----'
    tradestation_secretkey = '-----'
    tradestation_endpoint = '/brokerage/accounts'
    tradestation_accountid = '61999124,68910124' # ??
    param = {}
    param['since'] = '2022-05-01'
    url_value = urllib.parse.urlencode(param)
    full_url = base_url+tradestation_endpoint+"/"+tradestation_accountid+"/historicalorders"+"?"+url_value
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
    }
    request = urllib.request.Request(full_url, headers=headers)
    print(request.get_full_url())
    req_after_sign = tradestation_signature(request,tradestation_apikey,tradestation_secretkey)
    print(req_after_sign.get_full_url())

if __name__ == '__main__':
    ftx_api()