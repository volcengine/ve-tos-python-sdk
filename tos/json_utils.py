from tos.enum import PermissionType
from tos.models2 import Owner


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
        l = []
        for grant in grants:
            m = {}
            grantee = grant.grantee
            m['Grantee'] = {'ID': grantee.id, 'Type': grantee.type.value, 'DisplayName': grantee.display_name,
                            'Canned': grantee.canned.value}
            m['Permission'] = grant.permission.value
            l.append(m)
        data['Grants'] = l

    return data
