from enum import Enum

"""
统一枚举定义文件
"""


class ACLType(Enum):
    ACL_Unknown = "Unknown"
    ACL_Private = "private"
    ACL_Public_Read = "public-read"
    ACL_Public_Read_Write = "public-read-write"
    ACL_Authenticated_Read = "authenticated-read"
    ACL_Bucket_Owner_Read = "bucket-owner-read"
    ACL_Bucket_Owner_Full_Control = "bucket-owner-full-control"
    ACL_Bucket_Owner_Entrusted = "bucket-owner-entrusted"


def convert_acl_type(acl: str):
    for t in ACLType:
        if t.value == acl:
            return t
    return ACLType.ACL_Unknown


class InventoryFormatType(Enum):
    InventoryFormatCsv = "CSV"

class InventoryFrequencyType(Enum):
    InventoryFrequencyTypeDaily = "Daily"
    InventoryFrequencyTypeWeekly = "Weekly"

class InventoryIncludedObjType(Enum):
    InventoryIncludedObjTypeAll = "All"
    InventoryIncludedObjTypeCurrent = "Current"

class StorageClassType(Enum):
    Storage_Unknown = "Unknown"
    # 标准存储
    Storage_Class_Standard = "STANDARD"
    # 低频访问存储
    Storage_Class_Ia = "IA"
    # 智能分层存储
    Storage_Class_INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    # 归档闪回存储
    Storage_Class_Archive_Fr = 'ARCHIVE_FR'
    # 冷归档存储
    Storage_Class_Cold_Archive = 'COLD_ARCHIVE'
    # 归档存储
    Storage_Class_Archive = 'ARCHIVE'
    # 深度冷归档存储
    Storage_Class_DEEP_COLD_ARCHIVE = 'DEEP_COLD_ARCHIVE'

class TaggingDirectiveType(Enum):
    TaggingDirectiveTypeCopy = "Copy"
    TaggingDirectiveTypeReplace = "Replace"

def convert_storage_class_type(storage_class: str):
    for t in StorageClassType:
        if t.value == storage_class:
            return t
    return StorageClassType.Storage_Unknown


class MetadataDirectiveType(Enum):
    Metadata_Directive_Unknown = "Unknown"
    Metadata_Directive_Copy = "COPY"
    Metadata_Directive_Replace = "REPLACE"


def convert_metadata_directive_type(s: str):
    for t in MetadataDirectiveType:
        if t.value == s:
            return t
    return MetadataDirectiveType.Metadata_Directive_Unknown


class AzRedundancyType(Enum):
    Az_Redundancy_Unknown = "Unknown"
    Az_Redundancy_Single_Az = "single-az"
    Az_Redundancy_Multi_Az = "multi-az"


def convert_az_redundancy_type(s: str):
    for t in AzRedundancyType:
        if t.value == s:
            return t
    return AzRedundancyType.Az_Redundancy_Unknown


class PermissionType(Enum):
    Permission_Unknown = "Unknown"
    Permission_Read = "READ"
    Permission_Write = "WRITE"
    Permission_Read_Acp = "READ_ACP"
    Permission_Write_Acp = "WRITE_ACP"
    Permission_Full_Control = "FULL_CONTROL"


def convert_permission_type(s: str):
    for t in PermissionType:
        if t.value == s:
            return t
    return PermissionType.Permission_Unknown


class GranteeType(Enum):
    Grantee_Unknown = "Unknown"
    Grantee_Group = "Group"
    Grantee_User = "CanonicalUser"


def convert_grantee_type(s: str):
    for t in GranteeType:
        if t.value == s:
            return t
    return GranteeType.Grantee_Unknown


class CannedType(Enum):
    Canned_Unknown = "Unknown"
    Canned_All_Users = "AllUsers"
    Canned_Authenticated_Users = "AuthenticatedUsers"


def convert_canned_type(s: str):
    for t in CannedType:
        if t.value == s:
            return t
    return CannedType.Canned_Unknown


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
    Unknown = "Unknown"
    Mirror = "Mirror"
    Async = "Async"


def convert_redirect_type(s: str):
    for t in RedirectType:
        if t.value == s:
            return t
    return RedirectType.Unknown


class StatusType(Enum):
    Status_Unknown = "Unknown"
    Status_Enable = 'Enabled'
    Status_Disable = 'Disabled'


def convert_status_type(s: str):
    for t in StatusType:
        if t.value == s:
            return t
    return StatusType.Status_Unknown


class StorageClassInheritDirectiveType(Enum):
    Storage_Class_Unknown = "Unknown"
    Storage_Class_ID_Destination_Bucket = 'DESTINATION_BUCKET'
    Storage_Class_ID_Source_Object = 'SOURCE_OBJECT'


def convert_storage_class_inherit_directive_type(s: str):
    for t in StorageClassInheritDirectiveType:
        if t.value == s:
            return t
    return StorageClassInheritDirectiveType.Storage_Class_Unknown


class VersioningStatusType(Enum):
    Versioning_Unknown = "Unknown"
    Versioning_Status_Enabled = 'Enabled'
    Versioning_Status_Suspended = 'Suspended'


def convert_versioning_status_type(s: str):
    for t in VersioningStatusType:
        if t.value == s:
            return t
    return VersioningStatusType.Versioning_Unknown


class ProtocolType(Enum):
    Protocol_Unknown = "Unknown"
    Protocol_Http = 'http'
    Protocol_Https = 'https'


def convert_protocol_type(s: str):
    for t in ProtocolType:
        if t.value == s:
            return t
    return ProtocolType.Protocol_Unknown


class CertStatus(Enum):
    Cert_Unknown = "Unknown"
    Cert_Status_Bound = 'CertBound'
    Cert_Status_Unbound = 'CertUnbound'
    Cert_Status_Expired = 'CertExpired'


def convert_cert_status(s: str):
    for t in CertStatus:
        if t.value == s:
            return t
    return CertStatus.Cert_Unknown


class CopyEventType(Enum):
    Copy_Event_Create_Multipart_Upload_Succeed = 1
    Copy_Event_Create_Multipart_Upload_Failed = 2
    Copy_Event_Create_Part_Copy_Succeed = 3
    Copy_Event_Create_Part_Copy_Failed = 4
    Copy_Event_Create_Part_Copy_Aborted = 5
    Copy_Event_Completed_Multipart_Upload_Succeed = 6
    Copy_Event_Completed_Multipart_Upload_Failed = 7


class TierType(Enum):
    Tier_Unknown = "Unknown"
    Tier_Standard = "Standard"
    Tier_Expedited = "Expedited"
    Tier_Bulk = "Bulk"


def convert_tier_type(s: str):
    for t in TierType:
        if t.value == s:
            return t
    return TierType.Tier_Unknown


class ReplicationStatusType(Enum):
    ReplicationStatusType_Pending = "PENDING"
    ReplicationStatusType_Complete = "COMPLETE"
    ReplicationStatusType_Failed = "FAILED"
    ReplicationStatusType_Replica = "REPLICA"


def convert_replication_status_type(s: str):
    for t in ReplicationStatusType:
        if t.value == s:
            return t
    return ""

class QueryOrderType(Enum):
    ASC = "asc"
    DESC = "desc"

class QueryOperationType(Enum):
    NOT = "not"
    OR = "or"
    AND = "and"
    LT = "lt"
    GT = "gt"
    GTE = "gte"
    EQ = "eq"
    EXIST = "exist"
    PREFIX = "prefix"
    MatchPhrase = "match-phrase"

class AggregationOperationType(Enum):
    MIN = "min"
    MAX = "max"
    AVERAGE = "average"
    SUM = "sum"
    COUNT = "count"
    DISTINCT = "distinct"
    GROUP = "group"
class SemanticQueryType(Enum):
    SemanticQueryTypeText = "text"
    SemanticQueryTypeImage = "image"

class DataType(Enum):
    DataTypeFloat32 = "float32"
    DataTypeUnknown = "unknown"

def convert_data_type(s: str):
    for t in DataType:
        if t.value == s:
            return t
    return DataType.DataTypeFloat32

class DistanceMetricType(Enum):
    DistanceMetricEuclidean = "euclidean"
    DistanceMetricCosine = "cosine"
    DistanceMetricUnknown = "unknown"

def convert_distance_metric_type(s: str):
    for t in DistanceMetricType:
        if t.value == s:
            return t
    return DistanceMetricType.DistanceMetricUnknown