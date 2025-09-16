import json
from typing import Dict

from .consts import LAST_MODIFY_TIME_DATE_FORMAT
from .models2 import Owner, RedirectAllRequestsTo, IndexDocument, ErrorDocument, RoutingRules, CustomDomainRule, \
    RealTimeLogConfiguration, RestoreJobParameters, BucketEncryptionRule, QueryOrderType, QueryRequest, \
    AggregationRequest, BucketInventoryConfiguration, SemanticQueryType, ReplicationRule, Tag,Rule
from .utils import check_enum_type
from typing import List



def to_complete_multipart_upload_request(parts: list):
    dic = {}
    if parts is None:
        return dic
    p = []
    for part in parts:
        p.append({'PartNumber': part.part_number, 'ETag': part.etag})
    dic['Parts'] = p
    return dic


def to_delete_multi_objects_request(objects: [], quiet: bool, recursive: bool):
    data = {}
    if objects:
        obs = []
        for o in objects:
            obs.append({'Key': o.key, 'VersionId': o.version_id})
        data['Objects'] = obs
    data['Quiet'] = quiet
    return data


def to_put_acl_request(owner: Owner, grants: []):
    data = {}
    if owner:
        data['Owner'] = {"ID": owner.id, "DisplayName": owner.display_name}
    if grants:
        convertor_grant = []
        for grant in grants:
            m = {}
            grantee = grant.grantee
            check_enum_type(grantee=grantee.type, canned=grantee.canned, permission=grant.permission)
            m['Grantee'] = {'ID': grantee.id, 'Type': grantee.type.value, 'DisplayName': grantee.display_name}
            if grantee.canned:
                m['Grantee']['Canned'] = grantee.canned.value

            m['Permission'] = grant.permission.value
            convertor_grant.append(m)
        data['Grants'] = convertor_grant

    return data


def to_put_bucket_cors_request(cors_rules: []):
    data = {}
    arr = []
    for cors_rule in cors_rules:
        info = {}
        if cors_rule.allowed_origins:
            info['AllowedOrigins'] = cors_rule.allowed_origins
        if cors_rule.allowed_methods:
            info['AllowedMethods'] = cors_rule.allowed_methods
        if cors_rule.allowed_headers:
            info['AllowedHeaders'] = cors_rule.allowed_headers
        if cors_rule.expose_headers:
            info['ExposeHeaders'] = cors_rule.expose_headers
        if cors_rule.max_age_seconds:
            info['MaxAgeSeconds'] = cors_rule.max_age_seconds
        if cors_rule.response_vary:
            info['ResponseVary'] = cors_rule.response_vary
        arr.append(info)

    data['CORSRules'] = arr

    return data


def to_put_bucket_mirror_back(rules: List[Rule]):
    rules = rules or []
    data = {}
    arr = []
    for rule in rules:
        info = {}
        if rule.id:
            info['ID'] = rule.id
        if rule.condition:
            info['Condition'] = {}
            if rule.condition.http_code:
                info['Condition']['HttpCode'] = rule.condition.http_code
            if rule.condition.key_prefix:
                info['Condition']['KeyPrefix'] = rule.condition.key_prefix
            if rule.condition.key_suffix:
                info['Condition']['KeySuffix'] = rule.condition.key_suffix
            if rule.condition.http_method:
                info['Condition']['HttpMethod'] = rule.condition.http_method
            if rule.condition.allow_host:
                info['Condition']['AllowHost'] = rule.condition.allow_host
        if rule.redirect:
            info['Redirect'] = {}
            if rule.redirect.redirect_type:
                info['Redirect']['RedirectType'] = rule.redirect.redirect_type.value
            if rule.redirect.fetch_source_on_redirect is not None:
                info['Redirect']['FetchSourceOnRedirect'] = rule.redirect.fetch_source_on_redirect
            if rule.redirect.fetch_source_on_redirect_with_query is not None:
                info['Redirect']['FetchSourceOnRedirectWithQuery'] = rule.redirect.fetch_source_on_redirect_with_query
            if rule.redirect.public_source:
                info['Redirect']['PublicSource'] = {}
                if rule.redirect.public_source.source_endpoint:
                    info['Redirect']['PublicSource']['SourceEndpoint'] = {}
                    if rule.redirect.public_source.source_endpoint.primary:
                        info['Redirect']['PublicSource']['SourceEndpoint'][
                            'Primary'] = rule.redirect.public_source.source_endpoint.primary
                    if rule.redirect.public_source.source_endpoint.follower:
                        info['Redirect']['PublicSource']['SourceEndpoint'][
                            'Follower'] = rule.redirect.public_source.source_endpoint.follower
                if rule.redirect.public_source.fixed_endpoint is not None:
                    info['Redirect']['PublicSource']['FixedEndpoint'] = rule.redirect.public_source.fixed_endpoint
            if rule.redirect.private_source:
                info['Redirect']['PrivateSource'] = rule.redirect.private_source.to_dict()
            if rule.redirect.pass_query is not None:
                info['Redirect']['PassQuery'] = rule.redirect.pass_query
            if rule.redirect.follow_redirect is not None:
                info['Redirect']['FollowRedirect'] = rule.redirect.follow_redirect
            if rule.redirect.mirror_header:
                info['Redirect']['MirrorHeader'] = {}
                if rule.redirect.mirror_header.pass_all:
                    info['Redirect']['MirrorHeader']['PassAll'] = rule.redirect.mirror_header.pass_all
                if rule.redirect.mirror_header.pass_headers:
                    info['Redirect']['MirrorHeader']['Pass'] = rule.redirect.mirror_header.pass_headers
                if rule.redirect.mirror_header.remove:
                    info['Redirect']['MirrorHeader']['Remove'] = rule.redirect.mirror_header.remove
                if rule.redirect.mirror_header.set_header:
                    info['Redirect']['MirrorHeader']['Set'] = []
                    for one_kv in rule.redirect.mirror_header.set_header:
                        kv = {
                            'Key': one_kv.key,
                            'Value': one_kv.value
                        }
                        info['Redirect']['MirrorHeader']['Set'].append(kv)
            if rule.redirect.transform:
                info['Redirect']['Transform'] = {}
                if rule.redirect.transform.with_key_prefix:
                    info['Redirect']['Transform']['WithKeyPrefix'] = rule.redirect.transform.with_key_prefix
                if rule.redirect.transform.with_key_suffix:
                    info['Redirect']['Transform']['WithKeySuffix'] = rule.redirect.transform.with_key_suffix
                if rule.redirect.transform.replace_key_prefix:
                    info['Redirect']['Transform']['ReplaceKeyPrefix'] = {}
                    if rule.redirect.transform.replace_key_prefix.key_prefix:
                        info['Redirect']['Transform']['ReplaceKeyPrefix'][
                            'KeyPrefix'] = rule.redirect.transform.replace_key_prefix.key_prefix
                    if rule.redirect.transform.replace_key_prefix.replace_with:
                        info['Redirect']['Transform']['ReplaceKeyPrefix'][
                            'ReplaceWith'] = rule.redirect.transform.replace_key_prefix.replace_with
            if rule.redirect.fetch_header_to_meta_data_rules:
                meta_data_rules = []
                for r in rule.redirect.fetch_header_to_meta_data_rules:
                    meta_data_rule = {
                        'SourceHeader': r.source_header,
                        'MetaDataSuffix': r.meta_data_suffix
                    }
                    meta_data_rules.append(meta_data_rule)
                info['Redirect']['FetchHeaderToMetaDataRules'] = meta_data_rules
        arr.append(info)

    data['Rules'] = arr

    return data


def to_put_bucket_lifecycle(rules: []):
    data = {}
    arr = []
    for rule in rules:
        info = {}

        if rule.id:
            info['ID'] = rule.id

        if rule.prefix:
            info['Prefix'] = rule.prefix

        if rule.status:
            info['Status'] = rule.status.value

        if rule.expiration:
            info['Expiration'] = {}
            if rule.expiration.days:
                info['Expiration']['Days'] = rule.expiration.days
            if rule.expiration.date:
                info['Expiration']['Date'] = rule.expiration.date.strftime(LAST_MODIFY_TIME_DATE_FORMAT)

        if rule.no_current_version_expiration:
            info['NoncurrentVersionExpiration'] = {}
            if rule.no_current_version_expiration.no_current_days:
                info['NoncurrentVersionExpiration'][
                    'NoncurrentDays'] = rule.no_current_version_expiration.no_current_days
            if rule.no_current_version_expiration.non_current_date:
                info['NoncurrentVersionExpiration'][
                    'NoncurrentDate'] = rule.no_current_version_expiration.non_current_date.strftime(
                    LAST_MODIFY_TIME_DATE_FORMAT)

        if rule.abort_in_complete_multipart_upload and rule.abort_in_complete_multipart_upload.days_after_init:
            info['AbortIncompleteMultipartUpload'] = {
                'DaysAfterInitiation': rule.abort_in_complete_multipart_upload.days_after_init
            }

        if rule.tags:
            tag_arr = []
            for t in rule.tags:
                tag_arr.append({
                    'Key': t.key,
                    'Value': t.value
                })
            info['Tags'] = tag_arr

        if rule.transitions:
            trans_arr = []
            for t in rule.transitions:
                transition_info = {}
                if t.days:
                    transition_info['Days'] = t.days
                if t.date:
                    transition_info['Date'] = t.date.strftime(LAST_MODIFY_TIME_DATE_FORMAT)
                if t.storage_class:
                    transition_info['StorageClass'] = t.storage_class.value
                trans_arr.append(transition_info)
            info['Transitions'] = trans_arr

        if rule.non_current_version_transitions:
            current_version_transition_arr = []
            for tr in rule.non_current_version_transitions:
                non_current_version_transition_info = {}
                if tr.non_current_days:
                    non_current_version_transition_info['NoncurrentDays'] = tr.non_current_days
                if tr.storage_class:
                    non_current_version_transition_info['StorageClass'] = tr.storage_class.value
                if tr.non_current_date:
                    non_current_version_transition_info['NoncurrentDate'] = tr.non_current_date.strftime(
                        LAST_MODIFY_TIME_DATE_FORMAT)

                current_version_transition_arr.append(non_current_version_transition_info)

            info['NoncurrentVersionTransitions'] = current_version_transition_arr

        if rule.filter:
            info['Filter'] = {}
            if rule.filter.object_size_greater_than:
                info['Filter']['ObjectSizeGreaterThan'] = rule.filter.object_size_greater_than
            if rule.filter.greater_than_include_equal.value:
                info['Filter']['GreaterThanIncludeEqual'] = rule.filter.greater_than_include_equal.value
            if rule.filter.object_size_less_than:
                info['Filter']['ObjectSizeLessThan'] = rule.filter.object_size_less_than
            if rule.filter.less_than_include_equal.value:
                info['Filter']['LessThanIncludeEqual'] = rule.filter.less_than_include_equal.value
        arr.append(info)

    data['Rules'] = arr
    return data


def to_put_tagging(tags: []):
    info = []
    for tag in tags:
        info.append({
            'Key': tag.key,
            'Value': tag.value
        })
    data = {'TagSet': {
        'Tags': info
    }}
    return data


def to_fetch_object(url: str, object: str = None, ignore_same_key=None, hex_md5=None, content_md5=None):
    info = {'URL': url}
    if object:
        info['Object'] = object
    if ignore_same_key:
        info['IgnoreSameKey'] = ignore_same_key
    if not content_md5 and hex_md5:
        content_md5 = hex_md5
    if content_md5:
        info['ContentMD5'] = content_md5

    return info


def to_put_fetch_object(url: str, object: str = None, ignore_same_key=None, hex_md5=None, content_md5=None,
                        callback_url=None, callback_host=None, callback_body=None, callback_body_type=None):
    info = to_fetch_object(url, object, ignore_same_key, hex_md5, content_md5, )
    if callback_url:
        info['CallbackUrl'] = callback_url
    if callback_host:
        info['CallbackHost'] = callback_host
    if callback_body:
        info['CallbackBody'] = callback_body
    if callback_body_type:
        info['CallbackBodyType'] = callback_body_type
    return info


def to_put_replication(role: str, rules:List[ReplicationRule]):
    rules = rules or []
    info = {}
    if role:
        info['Role'] = role
    r = []
    for rule in rules:
        data = {}
        if rule.id:
            data['ID'] = rule.id
        if rule.status:
            data['Status'] = rule.status.value
        if rule.prefix_set:
            data['PrefixSet'] = rule.prefix_set
        if rule.destination:
            data['Destination'] = {}
            if rule.destination.bucket:
                data['Destination']['Bucket'] = rule.destination.bucket
            if rule.destination.location:
                data['Destination']['Location'] = rule.destination.location
            if rule.destination.storage_class:
                data['Destination']['StorageClass'] = rule.destination.storage_class.value
            if rule.destination.storage_class_inherit_directive:
                data['Destination'][
                    'StorageClassInheritDirective'] = rule.destination.storage_class_inherit_directive.value
        if rule.historical_object_replication:
            data['HistoricalObjectReplication'] = rule.historical_object_replication.value
        if rule.progress:
            data['Progress'] = {}
            if rule.progress.historical_object:
                data['Progress']['HistoricalObject'] = rule.progress.historical_object
            if rule.progress.new_object:
                data['Progress']['NewObject'] = rule.progress.new_object
        if rule.tags:
            data['Tags'] = [Tag.to_dict(t) for t in rule.tags]
        if rule.access_control_translation and rule.access_control_translation.owner:
            data['AccessControlTranslation'] = {"Owner": rule.access_control_translation.owner}
        r.append(data)
    info['Rules'] = r
    return info


def to_put_bucket_website(redirect_all_requests_to: RedirectAllRequestsTo,
                          index_document: IndexDocument, error_document: ErrorDocument, routing_rules: RoutingRules):
    info = {}
    if redirect_all_requests_to:
        info['RedirectAllRequestsTo'] = {}
        if redirect_all_requests_to.host_name:
            info['RedirectAllRequestsTo']['HostName'] = redirect_all_requests_to.host_name
        if redirect_all_requests_to.protocol:
            info['RedirectAllRequestsTo']['Protocol'] = redirect_all_requests_to.protocol
    if index_document:
        info['IndexDocument'] = {}
        if index_document.suffix:
            info['IndexDocument']['Suffix'] = index_document.suffix
        if index_document.forbidden_sub_dir:
            info['IndexDocument']['ForbiddenSubDir'] = index_document.forbidden_sub_dir

    if error_document:
        info['ErrorDocument'] = {}
        if error_document.key:
            info['ErrorDocument']['Key'] = error_document.key

    if routing_rules:
        info['RoutingRules'] = []
        if routing_rules.rules and len(routing_rules.rules) > 0:
            for rule in routing_rules.rules:
                rule_mp = {}
                if rule.condition:
                    rule_mp['Condition'] = {}
                    if rule.condition.key_prefix_equals:
                        rule_mp['Condition']['KeyPrefixEquals'] = rule.condition.key_prefix_equals
                    if rule.condition.http_error_code_returned_equals:
                        rule_mp['Condition'][
                            'HttpErrorCodeReturnedEquals'] = rule.condition.http_error_code_returned_equals
                if rule.redirect:
                    rule_mp['Redirect'] = {}
                    if rule.redirect.host_name:
                        rule_mp['Redirect']['HostName'] = rule.redirect.host_name
                    if rule.redirect.http_redirect_code:
                        rule_mp['Redirect']['HttpRedirectCode'] = rule.redirect.http_redirect_code
                    if rule.redirect.protocol:
                        rule_mp['Redirect']['Protocol'] = rule.redirect.protocol.value
                    if rule.redirect.replace_key_prefix_with:
                        rule_mp['Redirect']['ReplaceKeyPrefixWith'] = rule.redirect.replace_key_prefix_with
                    if rule.redirect.replace_key_with:
                        rule_mp['Redirect']['ReplaceKeyWith'] = rule.redirect.replace_key_with

                info['RoutingRules'].append(rule_mp)
    return info


def to_put_bucket_notification(cloudFunctionConfigurations: [], rocketMQConfigurations: []):
    info = {}
    if cloudFunctionConfigurations:
        info['CloudFunctionConfigurations'] = []
        for cloudFunctionConfiguration in cloudFunctionConfigurations:
            config = {}
            if cloudFunctionConfiguration.events:
                config['Events'] = cloudFunctionConfiguration.events
            if cloudFunctionConfiguration.id:
                config['RuleId'] = cloudFunctionConfiguration.id
            if cloudFunctionConfiguration.cloud_function:
                config['CloudFunction'] = cloudFunctionConfiguration.cloud_function
            if cloudFunctionConfiguration.filter:
                config['Filter'] = _get_bucket_notification_filter_map(cloudFunctionConfiguration.filter)
            info['CloudFunctionConfigurations'].append(config)

    if rocketMQConfigurations:
        info['RocketMQConfigurations'] = []
        for rocketMQConfiguration in rocketMQConfigurations:
            config = {}
            if rocketMQConfiguration.events:
                config['Events'] = rocketMQConfiguration.events
            if rocketMQConfiguration.id:
                config['RuleId'] = rocketMQConfiguration.id
            if rocketMQConfiguration.role:
                config['Role'] = rocketMQConfiguration.role
            if rocketMQConfiguration.rocket_mq:
                config['RocketMQ'] = {}
                if rocketMQConfiguration.rocket_mq.topic:
                    config['RocketMQ']['Topic'] = rocketMQConfiguration.rocket_mq.topic
                if rocketMQConfiguration.rocket_mq.access_key_id:
                    config['RocketMQ']['AccessKeyId'] = rocketMQConfiguration.rocket_mq.access_key_id
                if rocketMQConfiguration.rocket_mq.instance_id:
                    config['RocketMQ']['InstanceID'] = rocketMQConfiguration.rocket_mq.instance_id
            if rocketMQConfiguration.filter:
                config['Filter'] = _get_bucket_notification_filter_map(rocketMQConfiguration.filter)
            info['RocketMQConfigurations'].append(config)
    return info


def _get_bucket_notification_filter_map(filter: {}):
    filter_mp = {}
    if filter.key:
        filter_mp['TOSKey'] = {}
        if filter.key.rules and len(filter.key.rules) >= 1:
            filter_mp['TOSKey']['FilterRules'] = []
            for rule in filter.key.rules:
                rule_mp = {}
                if rule.name:
                    rule_mp['Name'] = rule.name
                if rule.value:
                    rule_mp['Value'] = rule.value
                filter_mp['TOSKey']['FilterRules'].append(rule_mp)
    return filter_mp


def to_put_custom_domain(custom_domain_rule: CustomDomainRule):
    info = {}
    if custom_domain_rule:
        info['CustomDomainRule'] = {}
        if custom_domain_rule.domain:
            info['CustomDomainRule']['Domain'] = custom_domain_rule.domain
        if custom_domain_rule.cname:
            info['CustomDomainRule']['Cname'] = custom_domain_rule.cname
        if custom_domain_rule.cert_id:
            info['CustomDomainRule']['CertId'] = custom_domain_rule.cert_id
        if custom_domain_rule.cert_status:
            info['CustomDomainRule']['CertStatus'] = custom_domain_rule.cert_status.value
        if custom_domain_rule.forbidden:
            info['CustomDomainRule']['Forbidden'] = custom_domain_rule.forbidden
        if custom_domain_rule.forbidden_reason:
            info['CustomDomainRule']['ForbiddenReason'] = custom_domain_rule.forbidden_reason

    return info


def to_put_bucket_real_time_log(configuation: RealTimeLogConfiguration):
    info = {}
    if configuation:
        info['RealTimeLogConfiguration'] = {}
        if configuation.role:
            info['RealTimeLogConfiguration']['Role'] = configuation.role
        if configuation.configuration:
            info['RealTimeLogConfiguration']['AccessLogConfiguration'] = {}
            if configuation.configuration.use_service_topic:
                info['RealTimeLogConfiguration']['AccessLogConfiguration'][
                    'UseServiceTopic'] = configuation.configuration.use_service_topic
            if configuation.configuration.tls_topic_id:
                info['RealTimeLogConfiguration']['AccessLogConfiguration'][
                    'TLSTopicID'] = configuation.configuration.tls_topic_id
            if configuation.configuration.tls_project_id:
                info['RealTimeLogConfiguration']['AccessLogConfiguration'][
                    'TLSProjectID'] = configuation.configuration.tls_project_id
    return info


def to_restore_object(days: int, tier: RestoreJobParameters):
    info = {}
    if days:
        info['Days'] = days
    if tier and tier.tier:
        info['RestoreJobParameters'] = {"Tier": tier.tier.value}

    return info

def to_semantic_query(dataset_name:str = None,
                      semantic_query_input:str =None,
                      semantic_query_type:SemanticQueryType =None,
                       max_results:int=100,with_fields:List[str]=None,query:QueryRequest=None):
    info = {}
    if dataset_name:
        info['DatasetName'] = dataset_name
    if semantic_query_input:
        info['SemanticQueryInput'] = semantic_query_input
    if semantic_query_type:
        info['SemanticQueryType'] = semantic_query_type.value
    if max_results > 0:
        info['MaxResults'] = max_results
    if with_fields:
        info['WithFields'] = with_fields
    if query:
        info['Query'] = query.to_dict()

    return json.dumps(info)


def to_simple_query(dataset_name:str = None,
                     sort:str= None,
                     order:QueryOrderType= None,
                     max_results:int= 100,
                     next_token:str = None,
                     with_fields:List[str] = None,
                     query:QueryRequest = None,
                     aggregations: List[AggregationRequest] = None):
    info = {}
    if dataset_name:
        info['DatasetName'] = dataset_name
    if sort:
        info['Sort'] = sort
    if order:
        info['Order'] = order.value
    if max_results>0:
        info['MaxResults'] = max_results
    if next_token:
        info['NextToken'] = next_token
    if with_fields:
        info['WithFields'] = with_fields
    if query:
        info['Query'] = query.to_dict()
    if aggregations:
        info['Aggregations'] = [a.to_dict() for a in aggregations]

    return json.dumps(info)



def to_bucket_encrypt(rule: BucketEncryptionRule):
    info = {}
    if rule and rule.apply_server_side_encryption_by_default:
        info['Rule'] = {}
        info['Rule']['ApplyServerSideEncryptionByDefault'] = {
            'SSEAlgorithm': rule.apply_server_side_encryption_by_default.sse_algorithm,
            'KMSMasterKeyID': rule.apply_server_side_encryption_by_default.kms_master_key_id
        }
    return info


def to_put_bucket_notification_type2(rules: [], version: str):
    info = {}
    if version:
        info['Version'] = version
    if rules:
        info['Rules'] = []
        for rule in rules:
            config = {'RuleID': rule.rule_id}
            if rule.events:
                config['Events'] = rule.events
            if rule.filter and rule.filter.tos_key and rule.filter.tos_key.filter_rules:
                config['Filter'] = {'TOSKey': {}}
                config_filter_rules = []
                for filter_rule in rule.filter.tos_key.filter_rules:
                    config_filter_rules.append({
                        'Name': filter_rule.name,
                        'Value': filter_rule.value,
                    })
                config['Filter']['TOSKey'] = {'FilterRules': config_filter_rules}
            if rule.destination:
                config['Destination'] = {}
                if rule.destination.rocket_mq:
                    rocket_mqs = []
                    for r in rule.destination.rocket_mq:
                        rocket_mq = {}
                        if r.role:
                            rocket_mq['Role'] = r.role
                        if r.instance_id:
                            rocket_mq['InstanceID'] = r.instance_id
                        if r.topic:
                            rocket_mq['Topic'] = r.topic
                        if r.access_key_id:
                            rocket_mq['AccessKeyID'] = r.access_key_id
                        rocket_mqs.append(rocket_mq)
                    config['Destination']['RocketMQ'] = rocket_mqs
                if rule.destination.ve_faas:
                    ve_faas = []
                    for r in rule.destination.ve_faas:
                        ve_faas.append({
                            'FunctionID': r.function_id
                        })
                    config['Destination']['VeFaaS'] = ve_faas

            info['Rules'].append(config)
    return info
