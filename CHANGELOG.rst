TOS SDK for Python 版本记录
===========================
Version 2.6.11
-------------
- 修复：get_fetch_task接口

Version 2.6.10
-------------
- 增加：get_fetch_task接口

Version 2.6.9
-------------
- 增加：软链接相关接口
- 增加：上传/拷贝对象等接口支持forbid_overwrite/if_match参数
- 增加：创建桶/列举桶支持project_name参数
- 增加：bucket_cors接口增加response_vary参数
- 增加：generic_input参数

Version 2.6.8
-------------
- 增加：BucketTagging相关接口
- 改变：重试时重新生成签名
- 改变：签名只签必要的Header

Version 2.6.7
-------------
- 修复：pre_signed_post_signature部分参数为可选

Version 2.6.6
-------------
- 增加：download_file 支持打印高延迟日志
- 增加：初始化参数新增 credential_provider 参数

Version 2.6.5
-------------
- 增加：DNS 缓存支持异步刷新和失效保护
- 增加：支持配置打印高延迟日志
- 增加：异常信息中新增 EC 详细错误码
- 增加：初始化的 Region 新增柔佛 ap-southeast-1
- 增加：初始化参数新增 socket_timeout 废弃 request_timeout
- 改变：重试策略适配服务端 Retry-After 机制
- 修复：优化了部分参数传入 bytes 类型值时的程序健壮性问题
- 修复：修复重试次数在某些场景下可能会放大的问题

Version 2.6.4
-------------
- 增加：数据处理持久化参数

Version 2.6.3
-------------
- 修复：修复 CHUNK 分块传输上传对象的 BUG

Version 2.6.1
-------------
- 修复：listobject控制台打印信息有误

Version 2.6.0
-------------
- 增加：支持单连接限速
- 增加：GetObject 支持设置图片转码参数
- 增加：CompleteMultipartUpload 接口支持 CompleteAll
- 增加：支持使用自定义域名，初始化参数新增 IsCustomDomain
- 增加：支持上传回调参数
- 增加：支持镜像回源参数增强
- 增加：支持重命名单个对象
- 增加：支持取回冷归档对象
- 增加：事件通知支持 MQ

Version 2.5.8
-------------
- 增加：支持归档、冷归档存储类型

Version 2.5.7
-------------
- 增加：签名接口解除最大7天限制

Version 2.5.6
-------------
- 增加：listv2默认返回owner信息

Version 2.5.5
-------------
- 修复：不支持枚举类型，添加默认unknown枚举值

Version 2.5.4
-------------
- 修复：删除resumable_copy_object中etag校验

Version 2.5.3
-------------
- 修复：上传对象时不支持大小为0的流

Version 2.5.2
-------------
- 修复：upload_file和put_object_from_file不支持空文件问题

Version 2.5.0
-------------
- 增加：桶跨区域复制相关接口
- 增加：桶多版本相关接口
- 增加：桶配置静态网站相关接口
- 增加：桶事件通知相关接口
- 增加：自定义域名相关接口
- 增加：断点续传复制接口
- 增加：目录分享签名接口
- 增加：列举对象v2接口
- 增加：获取桶元数据添加az字段
- 修复：追加写对象必填pre_crc问题

Version 2.4.2
-------------
- 增加：upload_file 和 download_file 支持加密
- 增加：自定义域名预签名
Version 2.4.1
-------------
- 增加：ListObjectsType2 接口
- 增加：桶生命周期相关接口
- 增加：桶策略相关接口
- 增加：桶存储类型相关接口
- 增加：桶CORS相关接口
- 增加: 桶镜像回源相关接口
- 增加: 桶ACL相关接口
- 增加: 对象标签相关接口
- 增加: fetch 相关接口
- 修复: copy 相关接口校验 etag
Version 2.3.4
-------------
- 修复：download_file 缺陷
- 修复：proxy 支持 https

Version 2.3.3
-------------
- 修复：删除不必要依赖

Version 2.3.2
-------------
- 修复：开启DNS缓存后，重复包装创建tcp连接问题
- 修复：部分字段类型

Version 2.3.1
-------------
- 修复：put_object_from_file 参数类型注解错误问题
- 修复：upload_part_copy 参数类型注解错误问题

Version 2.3.0
-------------
- 增加：断点续传下载功能
- 增加：客户端 CRC 校验功能
- 增加：客户端 DNS 缓存功能
- 增加：客户端断流校验功能
- 增加：进度条共功能
- 增加: 日志功能
- 增加: 上传下载客户端限速功能
- 改变：统一异常错误定义
- 增加：Proxy 功能

Version 2.1.0
-------------
- 改变：对齐各语言 SDK 使用接口与初始化客户端参数
- 增加：断点传输续传功能
- 增加：v2.1.0 相关unittest
- 改变：修改 User-Agent 命名规范
- 增加：v2.1.0 使用示例

Version 1.0.0
-------------
- 基于requests库构建 TOS Python SDK