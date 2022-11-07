from .consts import LAST_MODIFY_TIME_DATE_FORMAT
from .models2 import Owner
from .utils import check_enum_type


def to_complete_multipart_upload_request(parts: list):
    dic = {}
    p = []
    for part in parts:
        p.append({'PartNumber': part.part_number, 'ETag': part.etag})
    dic['Parts'] = p
    return dic


def to_delete_multi_objects_request(objects: [], quiet: bool):
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
        arr.append(info)

    data['CORSRules'] = arr

    return data


def to_put_bucket_mirror_back(rules: []):
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
            if rule.condition.object_key_prefix:
                info['Condition']['ObjectKeyPrefix'] = rule.condition.object_key_prefix
        if rule.redirect:
            info['Redirect'] = {}
            if rule.redirect.redirect_type:
                info['Redirect']['RedirectType'] = rule.redirect.redirect_type.value
            if rule.redirect.fetch_source_on_redirect is not None:
                info['Redirect']['FetchSourceOnRedirect'] = rule.redirect.fetch_source_on_redirect
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
            info['NoncurrentVersionExpiration'] = {
                'NoncurrentDays': rule.no_current_version_expiration.no_current_days
            }

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

                current_version_transition_arr.append(non_current_version_transition_info)

            info['NoncurrentVersionTransitions'] = current_version_transition_arr

        arr.append(info)

    data['Rules'] = arr

    return data


def to_put_object_tagging(tags: []):
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


def to_fetch_object(url: str, object: str = None, ignore_same_key=None, content_md5=None):
    info = {'URL': url}
    if object:
        info['Object'] = object
    if ignore_same_key:
        info['IgnoreSameKey'] = ignore_same_key
    if content_md5:
        info['ContentMD5'] = content_md5

    return info
