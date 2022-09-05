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


class StorageClassType(Enum):
    # 标准存储
    Storage_Class_Standard = "STANDARD"
    # 低频访问存储
    Storage_Class_Ia = "IA"

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
