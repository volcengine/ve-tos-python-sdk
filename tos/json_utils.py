from tos.models2 import Owner
from tos.utils import check_enum_type


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


def to_put_object_acl_request(owner: Owner, grants: []):
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
