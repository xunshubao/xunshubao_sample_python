# -*- coding: utf-8 -*-
# 本代码用来示例调用循数宝的V3版API接口
# 具体接口定义及描述请参考《涉诉数据接口文档》

import base64
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from gmssl.sm3 import sm3_hash
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


class ZxgkSearchForm:
    """
    执行公开查询表单
    """

    def __init__(self, requestId='', name='', cardNum='', hashParam='', hashType='', dataType='', publishDate='',
                 publishFromDate='', publishToDate='', delist='', caseCode='', pageNo=1, pageSize=10, extra=''):
        """
        执行公开查询条件
        :param requestId:请求唯一标识
        :param name:姓名
        :param cardNum:身份证号
        :param hashParam:使用哈希值的参数
        :param hashType:使用哈希的算法
        :param dataType: 数据类型
        :param publishDate: 发布日期
        :param publishFromDate: 发布日期开始
        :param publishToDate: 发布日期截止
        :param delist: 是否下架
        :param caseCode: 案号
        :param pageNo: 页码
        :param pageSize: 每页记录数
        :param extra:预留参数（原值返回），默认为空
        :return:
        """
        self.requestId = requestId
        self.name = name
        self.cardNum = cardNum
        self.hashParam = hashParam
        self.hashType = hashType
        self.dataType = dataType
        self.publishDate = publishDate
        self.publishFromDate = publishFromDate
        self.publishToDate = publishToDate
        self.delist = delist
        self.caseCode = caseCode
        self.pageNo = pageNo
        self.pageSize = pageSize
        self.extra = extra

    def request_body(self):
        return {
            'name': self.name,
            'cardNum': self.cardNum,
            'hashParam': self.hashParam,
            'hashType': self.hashType,
            'dataType': self.dataType,
            'publishDate': self.publishDate,
            'publishFromDate': self.publishFromDate,
            'publishToDate': self.publishToDate,
            'delist': self.delist,
            'caseCode': self.caseCode,
            'pageNo': self.pageNo,
            'pageSize': self.pageSize,
            'extra': self.extra
        }


class XunshubaoZxgkUtil:
    """
    执行公开核验/查询接口调用工具类
    """

    def __init__(self, appKey, signSecretKey, sm4SecretKey, aesSecretKey):
        self.appKey = appKey
        self.signSecretKey = signSecretKey
        self.sm4SecretKey = sm4SecretKey
        self.aesSecretKey = aesSecretKey
        self.timeout = 5

    def zxgk_check_for_company(self, search_form: ZxgkSearchForm):
        """
        执行公开核验接口-企业 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/zxgkcheck/company'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': search_form.requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('执行公开核验接口-企业查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("执行公开核验接口-企业查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('执行公开核验接口-企业请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zxgkCheckForPerson(self, search_form: ZxgkSearchForm):
        """
        执行公开核验接口-个人 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        url = 'https://api.xunshubao.com/v3/zxgkcheck/person'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # SM3签名
        token = self.sm3(token_src)

        # 请求头构建，使用SM4国密算法进行加解密
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'SM3',
            'requestId': search_form.requestId,
            'encryption': 'SM4'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptBySM4(self.sm4SecretKey, req_body_str)
        }

        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptBySM4(self.sm4SecretKey, encodedData)
                    logging.info('执行公开核验接口-个人查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("执行公开核验接口-个人查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('执行公开核验接口-个人请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def shixinCheckForCompany(self, search_form: ZxgkSearchForm):
        """
        失信核验接口-企业 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/shixincheck/company'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': search_form.requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('失信核验接口-企业查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("失信核验接口-企业查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('失信核验接口-企业请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def shixinCheckForPerson(self, search_form: ZxgkSearchForm):
        """
        失信核验接口-个人 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        url = 'https://api.xunshubao.com/v3/shixincheck/person'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # SM3签名
        token = self.sm3(token_src)

        # 请求头构建，使用SM4国密算法进行加解密
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'SM3',
            'requestId': search_form.requestId,
            'encryption': 'SM4'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptBySM4(self.sm4SecretKey, req_body_str)
        }

        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptBySM4(self.sm4SecretKey, encodedData)
                    logging.info('失信核验接口-个人查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("失信核验接口-个人查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('失信核验接口-个人请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def xglCheckForCompany(self, search_form: ZxgkSearchForm):
        """
        限制消费人员核验接口-企业 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/xglcheck/company'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': search_form.requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('限制消费核验接口-企业查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("限制消费核验接口-企业查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('限制消费核验接口-企业请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def xglCheckForPerson(self, search_form: ZxgkSearchForm):
        """
        限制消费人员核验接口-个人 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        url = 'https://api.xunshubao.com/v3/xglcheck/person'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # SM3签名
        token = self.sm3(token_src)

        # 请求头构建，使用SM4国密算法进行加解密
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'SM3',
            'requestId': search_form.requestId,
            'encryption': 'SM4'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptBySM4(self.sm4SecretKey, req_body_str)
        }

        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptBySM4(self.sm4SecretKey, encodedData)
                    logging.info('限制消费核验接口-个人查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("限制消费核验接口-个人查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('限制消费核验接口-个人请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zhixingCheckForCompany(self, search_form: ZxgkSearchForm):
        """
        被执行人核验接口-企业 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/zhixingcheck/company'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': search_form.requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('被执行人核验接口-企业查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("被执行人核验接口-企业查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('被执行人核验接口-企业请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zhixingCheckForPerson(self, search_form: ZxgkSearchForm):
        """
        被执行人核验接口-个人 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        url = 'https://api.xunshubao.com/v3/zhixingcheck/person'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # SM3签名
        token = self.sm3(token_src)

        # 请求头构建，使用SM4国密算法进行加解密
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'SM3',
            'requestId': search_form.requestId,
            'encryption': 'SM4'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptBySM4(self.sm4SecretKey, req_body_str)
        }

        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptBySM4(self.sm4SecretKey, encodedData)
                    logging.info('被执行人核验接口-个人查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("被执行人核验接口-个人查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('被执行人核验接口-个人请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zhongbenCheckForCompany(self, search_form: ZxgkSearchForm):
        """
        终本案件核验接口-企业 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/zhongbencheck/company'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': search_form.requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('终本案件核验接口-企业查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("终本案件核验接口-企业查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('终本案件核验接口-企业请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zhongbenCheckForPerson(self, search_form: ZxgkSearchForm):
        """
        终本案件核验接口-个人 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        url = 'https://api.xunshubao.com/v3/zhongbencheck/person'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # SM3签名
        token = self.sm3(token_src)

        # 请求头构建，使用SM4国密算法进行加解密
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'SM3',
            'requestId': search_form.requestId,
            'encryption': 'SM4'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptBySM4(self.sm4SecretKey, req_body_str)
        }

        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptBySM4(self.sm4SecretKey, encodedData)
                    logging.info('终本案件核验接口-个人查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("终本案件核验接口-个人查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('终本案件核验接口-个人请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zxgkQueryForCompany(self, search_form: ZxgkSearchForm):
        """
        执行公开查询接口-企业 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/zxgkquery/company'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': search_form.requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('执行公开查询接口-企业查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("执行公开查询接口-企业查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('执行公开查询接口-企业请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def zxgkQueryForPerson(self, search_form: ZxgkSearchForm):
        """
        执行公开查询接口-个人 请求示例
        :param search_form: 查询条件
        :return:元组（code, msg, result）
        """
        url = 'https://api.xunshubao.com/v3/zxgkquery/person'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = search_form.request_body()
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # SM3签名
        token = self.sm3(token_src)

        # 请求头构建，使用SM4国密算法进行加解密
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'SM3',
            'requestId': search_form.requestId,
            'encryption': 'SM4'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptBySM4(self.sm4SecretKey, req_body_str)
        }

        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptBySM4(self.sm4SecretKey, encodedData)
                    logging.info('执行公开查询接口-个人查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("执行公开查询接口-个人查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('执行公开查询接口-个人请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    def sifaDataInfo(self, requestId, dataType, dataId, extra=''):
        """
        执行公开数据详情 请求示例
        :param requestId: 请求唯一标识
        :param dataType: 数据类型
        :param dataId: 数据ID
        :param extra: 预留参数（原值返回），默认为空
        :return:元组（code, msg, result）
        """
        # 请求地址
        url = 'https://api.xunshubao.com/v3/sifa/datainfo'

        # 获取当前时间
        now = datetime.now()
        # 将当前时间转换为时间戳，并保留毫秒
        timestamp_ms = int(round(time.mktime(now.timetuple()) * 1000) + now.microsecond / 1000)

        # 业务请求参数构建
        req_body = {
            'dataType': dataType,
            'dataId': dataId,
            'extra': extra
        }
        # 业务请求参数转换为JSON字符串
        req_body_str = json.dumps(req_body)
        # 签名内容构建
        token_src = appKey + str(timestamp_ms) + self.signSecretKey + req_body_str
        # MD5签名
        token = self.md5(token_src)

        # 请求头构建
        req_header = {
            'appKey': appKey,
            'timestamp': timestamp_ms,
            'token': token,
            'signType': 'MD5',
            'requestId': requestId,
            'encryption': 'AES'
        }
        # 请求参数构建
        post_data = {
            'requestHeader': req_header,
            'requestBody': self.encryptByAES(self.aesSecretKey, req_body_str)
        }
        try:
            # 向服务器提交请求
            search_resp = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'},
                                        timeout=self.timeout)
            status_code = search_resp.status_code
            if search_resp.status_code == 200:
                search_result = search_resp.content.decode('utf-8').strip()
                contentJson = json.loads(search_result)
                code = contentJson['code']
                msg = contentJson['msg']
                if code == '0000':
                    encodedData = contentJson['data']
                    decodedTxt = self.decryptByAES(self.aesSecretKey, encodedData)
                    logging.info('执行公开数据详情查询成功，解密后的报文如下：')
                    logging.info(decodedTxt)
                    return code, msg, decodedTxt
                else:
                    logging.warning("执行公开数据详情查询不成功，错误代码=%s，错误信息=%s" % (code, msg))
                    return code, msg, None
            else:
                logging.warning('执行公开数据详情请求异常，响应状态码=%s' % status_code)
                return "9999", "响应状态码失败 status_code=%s" % status_code, None
        except Exception as rte:
            logging.warning(url, rte)
        return "9999", "请求异常", None

    # MD5方法
    def md5(self, token_src):
        m = hashlib.md5()
        m.update(token_src.encode('utf-8'))
        token = m.hexdigest()
        return token

    def sm3(self, txt):
        msg_list = [i for i in bytes(txt.encode('UTF-8'))]
        return sm3_hash(msg_list)

    def encryptByAES(self, key, txt):
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)  # 创建 AES 加密器对象
        padded_plaintext = pad(txt.encode('utf-8'), AES.block_size)  # 填充明文数据
        ciphertext = cipher.encrypt(padded_plaintext)  # 加密
        encoded_data = base64.b64encode(ciphertext)
        return encoded_data.decode('utf-8')

    def decryptByAES(self, key, ciphertext):
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)  # 创建 AES 加密器对象
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))  # 解密
        decrypted_data = unpad(decrypted, AES.block_size)  # 去除填充
        return decrypted_data.decode('utf-8')

    def encryptBySM4(self, key, txt):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(base64.b64decode(key), SM4_ENCRYPT)
        encrypt_value = crypt_sm4.crypt_ecb(txt.encode('utf-8'))  # bytes类型
        encoded_data = base64.b64encode(encrypt_value)
        return encoded_data.decode('utf-8')

    def decryptBySM4(self, key, ciphertext):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(base64.b64decode(key), SM4_DECRYPT)
        decrypt_value = crypt_sm4.crypt_ecb(base64.b64decode(ciphertext))  # bytes类型
        return decrypt_value.decode('utf-8')


if __name__ == "__main__":
    # 密钥，请联系销售获取
    # 用户标识
    appKey = ''
    # 签名密钥
    signSecretKey = ''
    # SM4密钥
    sm4SecretKey = ''
    # AES密钥
    aesSecretKey = ''

    # 配置日志
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # 查询条件
    # 企业名称（请替换为您要查询的企业）
    companyName = '某某公司'
    # 姓名 & 身份证号（请替换为您要查询的信息）
    name = '姓名'
    cardNum = '身份证号'

    # 初始化实例
    xunshubao_zxgk_util = XunshubaoZxgkUtil(appKey, signSecretKey, sm4SecretKey, aesSecretKey)

    # 执行公开核验接口-企业
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=companyName, pageNo=1)
    result = xunshubao_zxgk_util.zxgk_check_for_company(search_form)

    # 执行公开核验接口-个人
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=name, cardNum=cardNum, pageNo=1)
    xunshubao_zxgk_util.zxgkCheckForPerson(search_form)

    # 失信核验接口-企业
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=companyName, pageNo=1)
    result = xunshubao_zxgk_util.shixinCheckForCompany(search_form)

    # 失信核验接口-个人
    requestId = uuid.uuid4().hex
    encryptCardNum = xunshubao_zxgk_util.sm3(cardNum)
    search_form = ZxgkSearchForm(requestId=requestId, name=name, cardNum=encryptCardNum, hashParam='cardNum',
                                 hashType='SM3', pageNo=1)
    xunshubao_zxgk_util.shixinCheckForPerson(search_form)

    # 限制消费人员核验接口-企业
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=companyName, pageNo=1)
    result = xunshubao_zxgk_util.xglCheckForCompany(search_form)

    # 限制消费人员核验接口-个人
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=name, cardNum=cardNum, pageNo=1)
    xunshubao_zxgk_util.xglCheckForPerson(search_form)

    # 被执行人核验接口-企业
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=companyName, pageNo=1)
    result = xunshubao_zxgk_util.zhixingCheckForCompany(search_form)

    # 被执行人核验接口-个人
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=name, cardNum=cardNum, pageNo=1)
    xunshubao_zxgk_util.zhixingCheckForPerson(search_form)

    # 终本案件核验接口-企业
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=companyName, pageNo=1)
    result = xunshubao_zxgk_util.zhongbenCheckForCompany(search_form)

    # 终本案件核验接口-个人
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=name, cardNum=cardNum, pageNo=1)
    xunshubao_zxgk_util.zhongbenCheckForPerson(search_form)

    # 执行公开查询接口-企业
    caseCode = '案号'
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=companyName, caseCode=caseCode, pageNo=1)
    result = xunshubao_zxgk_util.zxgkQueryForCompany(search_form)

    # 执行公开查询接口-个人
    caseCode = '案号'
    requestId = uuid.uuid4().hex
    search_form = ZxgkSearchForm(requestId=requestId, name=name, cardNum=cardNum, caseCode=caseCode, pageNo=1)
    xunshubao_zxgk_util.zxgkQueryForPerson(search_form)

    # 司法数据详情
    dataType = 'zhixing'
    dataId = '7c8f5f4fa36c2ff011b0b012c38675de'
    requestId = uuid.uuid4().hex
    xunshubao_zxgk_util.sifaDataInfo(requestId, dataType, dataId)
