from enum import Enum

"""
统一枚举定义文件
"""


class ACLType(Enum):
    ACL_Private = "private"
    ACL_Public_Read = "public-read"
    ACL_Public_Read_Write = "public-read-write"
    ACL_Authenticated_Read = "authenticated-read"
    ACL_Bucket_Owner_Read = "bucket-owner-read"
    ACL_Bucket_Owner_Full_Control = "bucket-owner-full-control"
    ACL_Bucket_Owner_Entrusted = "bucket-owner-entrusted"


class StorageClassType(Enum):
    # 标准存储
    Storage_Class_Standard = "STANDARD"
    # 低频访问存储
    Storage_Class_Ia = "IA"
    # 归档闪回存储
    Storage_Class_Archive_Fr = 'ARCHIVE_FR'


class MetadataDirectiveType(Enum):
    Metadata_Directive_Copy = "COPY"
    Metadata_Directive_Replace = "REPLACE"


class AzRedundancyType(Enum):
    Az_Redundancy_Single_Az = "single-az"
    Az_Redundancy_Multi_Az = "multi-az"


class PermissionType(Enum):
    Permission_Read = "READ"
    Permission_Write = "WRITE"
    Permission_Read_Acp = "READ_ACP"
    Permission_Write_Acp = "WRITE_ACP"
    Permission_Full_Control = "FULL_CONTROL"


class GranteeType(Enum):
    Grantee_Group = "Group"
    Grantee_User = "CanonicalUser"


class CannedType(Enum):
    Canned_All_Users = "AllUsers"
    Canned_Authenticated_Users = "AuthenticatedUsers"


class HttpMethodType(Enum):
    Http_Method_Get = "GET"
    Http_Method_Put = "PUT"
    Http_Method_Post = "POST"
    Http_Method_Delete = "DELETE"
    Http_Method_Head = "HEAD"


class DataTransferType(Enum):
    Data_Transfer_Init = 0
    Data_Transfer_Started = 1
    Data_Transfer_RW = 2
    Data_Transfer_Succeed = 3
    Data_Transfer_Failed = 4


class UploadEventType(Enum):
    Upload_Event_Create_Multipart_Upload_Succeed = 1
    Upload_Event_Create_Multipart_Upload_Failed = 2
    Upload_Event_Upload_Part_Succeed = 3
    Upload_Event_Upload_Part_Failed = 4
    Upload_Event_UploadPart_Aborted = 5
    Upload_Event_Complete_Multipart_Upload_Succeed = 6
    Upload_Event_Complete_Multipart_Upload_Failed = 7


class DownloadEventType(Enum):
    Download_Event_Create_TempFile_Succeed = 1
    Download_Event_Create_Temp_File_Failed = 2
    Download_Event_Download_Part_Succeed = 3
    Download_Event_Download_Part_Failed = 4
    Download_Event_Download_Part_Aborted = 5
    Download_Event_Rename_Temp_File_Succeed = 6
    Download_Event_Rename_Temp_File_Failed = 7


class RedirectType(Enum):
    Mirror = "Mirror"
    Async = "Async"


class StatusType(Enum):
    Status_Enable = 'Enabled'
    Status_Disable = 'Disabled'


class StorageClassInheritDirectiveType(Enum):
    Storage_Class_ID_Destination_Bucket = 'DESTINATION_BUCKET'
    Storage_Class_ID_Source_Object = 'SOURCE_OBJECT'


class VersioningStatusType(Enum):
    Versioning_Status_Enabled = 'Enabled'
    Versioning_Status_Suspended = 'Suspended'


class ProtocolType(Enum):
    Protocol_Http = 'http'
    Protocol_Https = 'https'


class CertStatus(Enum):
    Cert_Status_Bound = 'CertBound'
    Cert_Status_Unbound = 'CertUnbound'
    Cert_Status_Expired = 'CertExpired'


class CopyEventType(Enum):
    Copy_Event_Create_Multipart_Upload_Succeed = 1
    Copy_Event_Create_Multipart_Upload_Failed = 2
    Copy_Event_Create_Part_Copy_Succeed = 3
    Copy_Event_Create_Part_Copy_Failed = 4
    Copy_Event_Create_Part_Copy_Aborted = 5
    Copy_Event_Completed_Multipart_Upload_Succeed = 6
    Copy_Event_Completed_Multipart_Upload_Failed = 7
