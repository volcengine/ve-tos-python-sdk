import json
import random
import time
import traceback
from typing import Dict, List, Any

import requests
from requests.adapters import HTTPAdapter

from tos import HttpMethodType, exceptions
from tos.auth import AnonymousAuth, CredentialProviderAuth
from tos.clientv2 import USER_AGENT, UNDEFINED, hook_request_log, _is_valid_bucket_name, _signed_req, \
    _handler_retry_policy
from tos.consts import CONNECT_TIMEOUT, UNSIGNED_PAYLOAD, CALLBACK_FUNCTION
from tos.enum import DataType, DistanceMetricType
from tos.exceptions import TosServerError, TosClientError
from tos.http import Request, Response
from tos.log import get_logger
from tos.models2 import PutVectorsOutput, Vector, VectorData, GetVectorsOutput, CreateVectorBucketOutput, DeleteVectorBucketOutput, ListVectorsOutput, QueryVectorsOutput, DistanceVector, DeleteVectorsOutput, CreateIndexOutput, DeleteIndexOutput, ListIndexesOutput, GetVectorBucketOutput, VectorBucket, GetIndexOutput, PutVectorBucketPolicyOutput, GetVectorBucketPolicyOutput, DeleteVectorBucketPolicyOutput, ListVectorBucketsOutput
from tos.safe_map import SafeMapFIFO
from tos.thread_ctx import consume_body
from tos.utils import _format_endpoint, _validate_account_id, generate_http_proxies, _build_user_agent, _to_case_insensitive_dict, \
    _sanitize_dict, _make_virtual_host_url, _get_host, _get_scheme, _get_vector_host, _make_virtual_host_uri, \
    _IterableAdapter, LogInfo, _get_sleep_time, get_value, _ReaderAdapter
from .credential import StaticCredentialsProvider


class VectorClient():
    def __init__(self, ak='', sk='', endpoint='', region='',
                 security_token=None,
                 max_retry_count=3,
                 max_connections=1024,
                 connection_time=10,
                 enable_verify_ssl=True,
                 dns_cache_time=15,
                 proxy_host: str = None,
                 proxy_port: int = None,
                 proxy_username: str = None,
                 proxy_password: str = None,
                 high_latency_log_threshold: int = 100,
                 socket_timeout=30,
                 credentials_provider=None,
                 except100_continue_threshold: int = 65536,
                 user_agent_product_name: str = None,
                 user_agent_soft_name: str = None,
                 user_agent_soft_version: str = None,
                 user_agent_customized_key_values: Dict[str, str] = None):
        """创建client
                :param ak: Access Key ID: 访问密钥ID，用于标识用户
                :param sk: Secret Access Key: 与访问密钥ID结合使用的密钥，用于加密签名
                :param security_token: 临时鉴权 Token
                :param endpoint: TOS 服务端域名，完整格式：https://{host}:{port}
                :param region: TOS 服务端所在区域
                :param max_retry_count: 请求失败后最大的重试次数。默认3次
                :param connection_time: 建立连接超时时间，单位：秒，默认 10 秒
                :param max_connections: 连接池中允许打开的最大 HTTP 连接数，默认 1024
                :param enable_verify_ssl: 是否开启 SSL 证书校验，默认为 true
                :param dns_cache_time: DNS 缓存的有效期，单位：分钟，小于等于 0 时代表关闭 DNS 缓存，默认为 15
                :param proxy_host: 代理服务器的主机地址，当前只支持 http 协议
                :param proxy_port: 代理服务器的端口
                :param proxy_username: 连接代理服务器时使用的用户名
                :param proxy_password: 代理服务使用的密码
                :param high_latency_log_threshold: 大于 0 时，代表开启高延迟日志，单位：KB，默认为 100，当单次请求传输总速率低于该值且总请求耗时大于 500 毫秒时打印 WARN 级别日志
                :param socket_timeout: 连接建立成功后，单个请求的 Socket 读写超时时间，单位：秒，默认 30 秒，参考: https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts
                :param user_agent_product_name: 业务方/产品名
                :param user_agent_soft_name: user_agent扩展，软件名
                :param user_agent_soft_version: user_agent扩展，软件版本号
                :param user_agent_customized_key_values: user_agent扩展，自定义扩展 KV 键值对
                :return VectorClient:
                """
        endpoint = endpoint if isinstance(endpoint, str) else endpoint.decode() if isinstance(endpoint, bytes) else str(
            endpoint)

        endpoint = endpoint.strip()
        self.session = requests.Session()

        if ak == "" and sk == "" and credentials_provider is None:
            self.auth = AnonymousAuth(ak, sk, region, sts=security_token)
        else:
            if credentials_provider is None:
                credentials_provider = StaticCredentialsProvider(ak, sk, security_token)
            self.auth = CredentialProviderAuth(credentials_provider, region, service='tosvectors')

        self.endpoint = _format_endpoint(endpoint)
        self.host = _get_host(self.endpoint)
        self.scheme = _get_scheme(self.endpoint)
        self.timeout = connection_time or CONNECT_TIMEOUT
        self.max_retry_count = max_retry_count if max_retry_count >= 0 else 0
        self.dns_cache_time = dns_cache_time * 60 if dns_cache_time > 0 else 0
        self.connection_time = connection_time if connection_time > 0 else 10
        self.enable_verify_ssl = enable_verify_ssl
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.proxies = generate_http_proxies(proxy_host, proxy_port, proxy_username, proxy_password)
        self.high_latency_log_threshold = high_latency_log_threshold if high_latency_log_threshold >= 0 else 0
        self.socket_timeout = socket_timeout if socket_timeout > 0 else 30
        self.except100_continue_threshold = except100_continue_threshold
        self.user_agent = _build_user_agent(USER_AGENT, user_agent_product_name, user_agent_soft_name,
                                            user_agent_soft_version,user_agent_customized_key_values,UNDEFINED)

        # 通过 hook 机制实现in-request log
        self.session.hooks['response'].append(hook_request_log)

        self.session.mount('http://', HTTPAdapter(pool_connections=max_connections,
                                                  pool_maxsize=max_connections, max_retries=0))
        self.session.mount('https://', HTTPAdapter(pool_connections=max_connections,
                                                   pool_maxsize=max_connections, max_retries=0))

    def _make_virtual_host_url(self, bucket=None, account_id=None,action=None):
        return _make_virtual_host_url(self.host, self.scheme, bucket,action,account_id)

    def _req(self, bucket=None, action=None, method=None, data=None, headers=None, params=None, func=None,
             generic_input=None, account_id=None):
        consume_body()
        # 获取调用方法的名称
        func_name = func or traceback.extract_stack()[-2][2]

        headers = _to_case_insensitive_dict(headers)
        params = _sanitize_dict(params)


        if headers.get('x-tos-content-sha256') is None:
            headers['x-tos-content-sha256'] = UNSIGNED_PAYLOAD

        # 通过变量赋值,防止动态调整 auth endpoint 出现并发问题
        auth = self.auth
        endpoint = self.endpoint
        if bucket is not None:
            _is_valid_bucket_name(bucket)


        req_url = self._make_virtual_host_url(bucket, account_id,action)
        req_host = _get_vector_host(bucket,account_id,endpoint)

        req = Request(method, req_url,
                      _make_virtual_host_uri(action),
                      req_host,
                      data=data,
                      params=params,
                      headers=headers,
                      generic_input=generic_input)

        # 若为网络流对象删除headers中的content-length，防止签名计算错误
        if isinstance(data, _IterableAdapter) and headers.get('content-length'):
            del req.headers['content-length']

        # 若auth 为空即为匿名请求，则不计算签名
        if auth is not None:
            auth.sign_request(req)

        if 'User-Agent' not in req.headers:
            req.headers['User-Agent'] = self.user_agent

        # 通过变量赋值，防止动态调整 max_retry_count 出现并发问题
        retry_count = self.max_retry_count
        rsp = None
        host = headers['Host']
        for i in range(0, retry_count + 1):
            info = LogInfo()
            # 采用指数避让策略
            if i != 0:
                sleep_time = _get_sleep_time(rsp, i)
                get_logger().info('in-request: sleep {}s'.format(sleep_time))
                time.sleep(sleep_time)
                req.headers['x-sdk-retry-count'] = 'attempt=' + str(i) + '; max=' + str(retry_count)
                req = _signed_req(auth, req, host)
            try:
                # 对于网络流的对象, 删除header中的 host 元素
                # 对于能获取大小的流对象，但size==0, 删除header中的 host 元素
                if isinstance(data, _IterableAdapter) or (isinstance(data, _ReaderAdapter) and data.size == 0):
                    del req.headers['Host']
                # 由于TOS的重定向场景尚未明确, 目前关闭重定向功能
                stream = False if method == HttpMethodType.Http_Method_Head.value else True
                res = self.session.request(method,
                                           req.url,
                                           data=req.data,
                                           headers=req.headers,
                                           params=req.params,
                                           stream=stream,
                                           timeout=(self.connection_time, self.socket_timeout),
                                           verify=self.enable_verify_ssl,
                                           proxies=self.proxies,
                                           allow_redirects=False)
                rsp = Response(res)
                if rsp.status >= 300 or (rsp.status == 203 and func_name in CALLBACK_FUNCTION):
                    raise exceptions.make_server_error(rsp)

                content_length = get_value(rsp.headers, 'content-length', int)
                if content_length is not None and content_length == 0:
                    rsp.read()
                info.success(func_name, rsp)
                return rsp

            except (requests.RequestException, TosServerError) as e:
                get_logger().info('Exception: %s', e)
                if isinstance(e, TosServerError):
                    can_retry = _handler_retry_policy(req.data, method, func_name, server_exp=e)
                    exp = e
                else:
                    can_retry = _handler_retry_policy(req.data, method, func_name, client_exp=e)
                    exp = TosClientError('http request timeout', e)

                if can_retry and i < retry_count:
                    get_logger().info(
                        'in-request: retry success data:{} method:{} func_name:{}, exp:{}'.format(req.data, method,
                                                                                                  func_name, exp))
                    continue
                get_logger().info(
                    'in-request: retry fail data:{} method:{} func_name:{}, exp:{}'.format(req.data, method,
                                                                                           func_name, e))

                exp.request_url = req.get_request_url()
                info.fail(func_name, exp)
        return None

    def create_vector_bucket(self, vector_bucket_name: str,
                           generic_input=None) -> CreateVectorBucketOutput:
        """创建向量存储桶
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param generic_input: 通用参数（可选）
        :return: CreateVectorBucketOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            action='CreateVectorBucket',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return CreateVectorBucketOutput(resp)

    def get_vector_bucket(self, vector_bucket_name: str, account_id: str,
                          generic_input=None) -> GetVectorBucketOutput:
        """获取向量存储桶信息
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param generic_input: 通用参数（可选）
        :return: GetVectorBucketOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='GetVectorBucket',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return GetVectorBucketOutput(resp)

    def put_vectors(self, vector_bucket_name: str, account_id: str, index_name: str, 
                    vectors: List[Vector], generic_input=None) -> PutVectorsOutput:
        """批量写入向量数据
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称
        :param vectors: 向量数据列表
        :param generic_input: 通用参数（可选）
        :return: PutVectorsOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        if not vectors:
            raise TosClientError('vectors is required')
        
        # 2. 构建请求体
        body = {
            'indexName': index_name,
            'vectorBucketName': vector_bucket_name,
            'vectors': []
        }
        
        for vector in vectors:
            vector_dict = {
                'key': vector.key,
                'data': {}
            }
            
            if vector.data and vector.data.float32:
                vector_dict['data']['float32'] = vector.data.float32
            
            if vector.metadata:
                vector_dict['metadata'] = vector.metadata
                
            body['vectors'].append(vector_dict)
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='PutVectors',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return PutVectorsOutput(resp)

    def get_vectors(self, vector_bucket_name: str, account_id: str, index_name: str,
                    keys: List[str], return_data: bool = False, return_metadata: bool = False,
                    generic_input=None) -> GetVectorsOutput:
        """批量获取向量数据
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称
        :param keys: 向量键列表
        :param return_data: 是否返回向量数据（可选，默认False）
        :param return_metadata: 是否返回向量元数据（可选，默认False）
        :param generic_input: 通用参数（可选）
        :return: GetVectorsOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        if not keys:
            raise TosClientError('keys is required')
        
        # 2. 构建请求体
        body = {
            'indexName': index_name,
            'keys': keys,
            'returnData': return_data,
            'returnMetadata': return_metadata,
            'vectorBucketName': vector_bucket_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='GetVectors',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return GetVectorsOutput(resp)

    def delete_vector_bucket(self, vector_bucket_name: str, account_id: str,
                             generic_input=None) -> DeleteVectorBucketOutput:
        """删除向量存储桶
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param generic_input: 通用参数（可选）
        :return: DeleteVectorBucketOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='DeleteVectorBucket',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return DeleteVectorBucketOutput(resp)

    def list_vectors(self, vector_bucket_name: str, index_name: str, account_id: str,
                     max_results: int = None, next_token: str = None,
                     return_data: bool = None, return_metadata: bool = None,
                     generic_input=None) -> ListVectorsOutput:
        """批量列举向量数据
        
        :param vector_bucket_name: 向量存储桶名称
        :param index_name: 向量索引名称
        :param account_id: 账户ID
        :param max_results: 最大返回结果数（可选）
        :param next_token: 分页令牌（可选）
        :param return_data: 是否返回向量数据（可选）
        :param return_metadata: 是否返回向量元数据（可选）
        :param generic_input: 通用参数（可选）
        :return: ListVectorsOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        
        # 2. 构建请求体
        body = {
            'indexName': index_name,
            'vectorBucketName': vector_bucket_name
        }
        
        # 添加可选参数
        if max_results is not None:
            body['maxResults'] = max_results
        if next_token is not None:
            body['nextToken'] = next_token
        if return_data is not None:
            body['returnData'] = return_data
        if return_metadata is not None:
            body['returnMetadata'] = return_metadata
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='ListVectors',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return ListVectorsOutput(resp)

    def query_vectors(self, vector_bucket_name: str, account_id: str, index_name: str,
                     query_vector: VectorData, top_k: int = 10, return_distance: bool = False,
                     return_metadata: bool = False, filter: Dict[str, Any] = None,
                     generic_input=None) -> QueryVectorsOutput:
        """向量搜索
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称
        :param query_vector: 查询向量数据
        :param top_k: 返回最相似的K个向量（可选，默认10）
        :param return_distance: 是否返回距离（可选，默认False）
        :param return_metadata: 是否返回元数据（可选，默认False）
        :param filter: 过滤条件（可选）
        :param generic_input: 通用参数（可选）
        :return: QueryVectorsOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        if not query_vector:
            raise TosClientError('query_vector is required')
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name,
            'indexName': index_name,
            'returnDistance': return_distance,
            'returnMetadata': return_metadata,
            'topK': top_k,
            'queryVector': {}
        }
        
        # 处理查询向量数据
        if query_vector.float32:
            body['queryVector']['float32'] = query_vector.float32
        
        if filter:
            body['filter'] = filter
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='QueryVectors',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return QueryVectorsOutput(resp)

    def delete_vectors(self, vector_bucket_name: str, account_id: str, index_name: str,
                      keys: List[str], generic_input=None) -> DeleteVectorsOutput:
        """批量删除向量数据
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称
        :param keys: 要删除的向量键列表
        :param generic_input: 通用参数（可选）
        :return: DeleteVectorsOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        if not keys:
            raise TosClientError('keys is required')
        
        # 2. 构建请求体
        body = {
            'indexName': index_name,
            'keys': keys,
            'vectorBucketName': vector_bucket_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='DeleteVectors',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return DeleteVectorsOutput(resp)

    def create_index(self, vector_bucket_name: str, account_id: str, index_name: str,
                     data_type: DataType = None, dimension: int = None, distance_metric: DistanceMetricType = None,
                     metadata_configuration: Dict[str, Any] = None, generic_input=None) -> CreateIndexOutput:
        """创建向量索引
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称
        :param data_type: 数据类型（可选）
        :param dimension: 向量维度（可选）
        :param distance_metric: 距离度量类型（可选）
        :param metadata_configuration: 元数据配置（可选）
        :param generic_input: 通用参数（可选）
        :return: CreateIndexOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name,
            'indexName': index_name
        }
        
        # 添加可选参数
        if data_type is not None:
            body['dataType'] = data_type.value
        if dimension is not None:
            body['dimension'] = dimension
        if distance_metric is not None:
            body['distanceMetric'] = distance_metric.value
        if metadata_configuration is not None:
            body['metadataConfiguration'] = metadata_configuration
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='CreateIndex',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return CreateIndexOutput(resp)

    def delete_index(self, vector_bucket_name: str, account_id: str, index_name: str,
                     generic_input=None) -> DeleteIndexOutput:
        """删除向量索引
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称（可选）
        :param generic_input: 通用参数（可选）
        :return: DeleteIndexOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name,
            'indexName': index_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='DeleteIndex',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return DeleteIndexOutput(resp)

    def list_indexes(self, vector_bucket_name: str, account_id: str,
                     max_results: int = None, next_token: str = None, 
                     prefix: str = None, generic_input=None) -> ListIndexesOutput:
        """列举向量索引
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param max_results: 最大返回结果数（可选）
        :param next_token: 分页令牌（可选）
        :param prefix: 索引名称前缀（可选）
        :param generic_input: 通用参数（可选）
        :return: ListIndexesOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        
        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name
        }
        
        # 添加可选参数
        if max_results is not None:
            body['maxResults'] = max_results
        if next_token is not None:
            body['nextToken'] = next_token
        if prefix is not None:
            body['prefix'] = prefix
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='ListIndexes',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return ListIndexesOutput(resp)

    def get_index(self, vector_bucket_name: str, account_id: str, index_name: str,
                  generic_input=None) -> GetIndexOutput:
        """获取向量索引信息
        
        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param index_name: 向量索引名称
        :param generic_input: 通用参数（可选）
        :return: GetIndexOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not index_name:
            raise TosClientError('index_name is required')
        
        # 2. 构建请求体
        body = {
            'indexName': index_name,
            'vectorBucketName': vector_bucket_name
        }
        
        # 3. 构建请求头
        headers = {}
        
        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='GetIndex',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )
        
        # 5. 构建返回值
        return GetIndexOutput(resp)
    def put_vector_bucket_policy(self, vector_bucket_name: str, account_id: str, policy: str,
                                   generic_input=None):
        """设置向量存储桶策略

        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param policy: 策略内容
        :param generic_input: 通用参数（可选）
        :return: PutVectorBucketPolicyOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)
        if not policy:
            raise TosClientError('policy is required')

        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name,
            'policy': policy
        }

        # 3. 构建请求头
        headers = {}

        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='PutVectorBucketPolicy',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )

        # 5. 构建返回值
        return PutVectorBucketPolicyOutput(resp)

    def get_vector_bucket_policy(self, vector_bucket_name: str, account_id: str,
                                   generic_input=None) -> GetVectorBucketPolicyOutput:
        """获取向量存储桶策略

        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param generic_input: 通用参数（可选）
        :return: GetVectorBucketPolicyOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)

        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name
        }

        # 3. 构建请求头
        headers = {}

        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='GetVectorBucketPolicy',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )

        # 5. 构建返回值
        return GetVectorBucketPolicyOutput(resp)

    def delete_vector_bucket_policy(self, vector_bucket_name: str, account_id: str,
                                   generic_input=None) -> DeleteVectorBucketPolicyOutput:
        """删除向量存储桶策略

        :param vector_bucket_name: 向量存储桶名称
        :param account_id: 账户ID
        :param generic_input: 通用参数（可选）
        :return: DeleteVectorBucketPolicyOutput
        """
        # 1. 参数验证
        _is_valid_bucket_name(vector_bucket_name)
        _validate_account_id(account_id)

        # 2. 构建请求体
        body = {
            'vectorBucketName': vector_bucket_name
        }

        # 3. 构建请求头
        headers = {}

        # 4. 发送请求
        resp = self._req(
            bucket=vector_bucket_name,
            action='DeleteVectorBucketPolicy',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            account_id=account_id,
            generic_input=generic_input
        )

        # 5. 构建返回值
        return DeleteVectorBucketPolicyOutput(resp)

    def list_vector_buckets(self, prefix: str = None, next_token: str = None, 
                           max_results: int = None, generic_input=None) -> ListVectorBucketsOutput:
        """列举向量存储桶
        
        :param prefix: 向量存储桶名称前缀（可选）
        :param next_token: 分页令牌（可选）
        :param max_results: 最大返回结果数（可选）
        :param project_name: 项目名称（可选）
        :param generic_input: 通用参数（可选）
        :return: ListVectorBucketsOutput
        """
        # 1. 构建请求体
        body = {}
        
        # 添加可选参数
        if prefix is not None:
            body['prefix'] = prefix
        if next_token is not None:
            body['nextToken'] = next_token
        if max_results is not None:
            body['maxResults'] = max_results
        
        # 2. 构建请求头
        headers = {}
        
        # 3. 发送请求
        resp = self._req(
            action='ListVectorBuckets',
            method=HttpMethodType.Http_Method_Post.value,
            data=json.dumps(body),
            headers=headers,
            generic_input=generic_input
        )
        
        # 4. 构建返回值
        return ListVectorBucketsOutput(resp)
