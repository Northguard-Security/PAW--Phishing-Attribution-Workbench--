"""Bounded headers across the existing parser tree; claims remain unverified."""
from dataclasses import dataclass
import hashlib

from .header_inventory import HeaderInventoryLimits, _inventory_headers
from .mime_analysis import MimeLimits, MimeLimitExceeded


@dataclass(frozen=True)
class MimeHeaderInventoryLimits:
    max_parts: int = 500
    max_depth: int = 30
    max_fields_per_part: int = 1024
    max_fields: int = 4096
    max_name_bytes: int = 256
    max_value_bytes: int = 16384
    max_raw_bytes_per_part: int = 262144
    max_raw_bytes: int = 1048576
    max_parsed_bytes: int = 2097152


def _tree(message, mime_limits):
    # Full traversal is bounded by existing parser-tree limits, including nodes
    # below attached messages. No payload decoding or nested sender analysis.
    stack = [(message, '0', None, 0, '0', None, '0', 'outer_message')]
    count = 0
    while stack:
        node = stack.pop()
        part, path, parent, depth, root, enclosing, outer, role = node
        count += 1
        if count > mime_limits.max_parts or depth > mime_limits.max_depth:
            raise MimeLimitExceeded('MIME part/depth limit exceeded')
        yield node
        payload = part.get_payload()
        if not isinstance(payload, list):
            continue
        composite_message = part.get_content_maintype() == 'message'
        for index in reversed(range(len(payload))):
            child_path = path+'.'+str(index)
            child_root = child_path if composite_message else root
            child_enclosing = path if composite_message else enclosing
            child_outer = outer if enclosing is not None else (path if composite_message else child_path)
            child_role = ('encapsulated_message' if part.get_content_type() == 'message/rfc822'
                          else 'parser_message_block') if composite_message else 'mime_part'
            stack.append((payload[index], child_path, path, depth+1,
                          child_root, child_enclosing, child_outer, child_role))


def inventory_mime_headers(message, original, limits=MimeHeaderInventoryLimits(), mime_limits=MimeLimits()):
    for name, value in vars(limits).items():
        if type(value) is not int or value < (0 if name == 'max_depth' else 1):
            raise ValueError('MIME header limits must be positive integers; depth may be zero')
    if len(original) > mime_limits.max_input_bytes:
        raise MimeLimitExceeded('Input email byte limit exceeded')
    source = {'path':'input.eml', 'sha256':hashlib.sha256(original).hexdigest()}
    result = {'schema_version':1, 'scope':'parser_recognized_mime_tree_headers',
        'verified':False, 'source':source, 'limits':dict(vars(limits)),
        'parser_tree_limits':dict(vars(mime_limits)), 'parts':[], 'issues':[],
        'total_part_count':0, 'total_field_count':0, 'omitted_part_count':0,
        'inventoried_field_count':0, 'limited_field_count':0,
        'captured_raw_bytes':0, 'captured_parsed_bytes':0,
        'limitation':'Parser header values, not exact field byte spans or authentication; embedded claims do not describe the outer sender. Exact original: input.eml.'}
    for part, path, parent, depth, root, enclosing, outer, role in _tree(message, mime_limits):
        result['total_part_count'] += 1
        result['total_field_count'] += len(part)
        if len(result['parts']) >= limits.max_parts or depth > limits.max_depth:
            result['omitted_part_count'] += 1
            issue = 'part_count_limit' if len(result['parts']) >= limits.max_parts else 'depth_limit'
            if issue not in result['issues']: result['issues'].append(issue)
            continue
        remaining_fields = limits.max_fields-result['inventoried_field_count']
        remaining_raw = limits.max_raw_bytes-result['captured_raw_bytes']
        remaining_parsed = limits.max_parsed_bytes-result['captured_parsed_bytes']
        field_limits = HeaderInventoryLimits(
            max_fields=min(limits.max_fields_per_part, remaining_fields),
            max_name_bytes=limits.max_name_bytes, max_value_bytes=limits.max_value_bytes,
            max_raw_bytes=min(limits.max_raw_bytes_per_part, remaining_raw))
        headers = _inventory_headers(part, source, field_limits,
            'parser_recognized_entity_headers', parsed_budget=remaining_parsed)
        if part.get_content_maintype() == 'multipart' and role == 'mime_part':
            role = 'mime_container'
        result['parts'].append({'part_id':path, 'parent_part_id':parent, 'depth':depth,
            'message_root_part_id':root, 'enclosing_message_part_id':enclosing,
            'outer_mime_part_id':outer, 'role':role,
            'content_type':part.get_content_type(), 'headers':headers})
        result['inventoried_field_count'] += headers['inventoried_field_count']
        result['limited_field_count'] += headers['limited_field_count']
        result['captured_raw_bytes'] += headers['captured_raw_bytes']
        result['captured_parsed_bytes'] += sum(len(field['parsed_value'].encode('utf-8'))
            for field in headers['fields'] if field['parsed_value'] is not None)
    result['inventoried_part_count'] = len(result['parts'])
    result['omitted_field_count'] = result['total_field_count']-result['inventoried_field_count']
    result['partial_part_count'] = sum(part['headers']['status'] != 'completed' for part in result['parts'])
    result['status'] = 'partial' if result['issues'] or result['partial_part_count'] else 'completed'
    return result


def mime_header_coverage(inventory):
    keys = ('status', 'scope', 'verified', 'total_part_count', 'inventoried_part_count',
            'omitted_part_count', 'total_field_count', 'inventoried_field_count',
            'omitted_field_count', 'limited_field_count', 'partial_part_count')
    return {**{key:inventory[key] for key in keys}, 'artifact':'mime_header_inventory.json',
            'limitation':inventory['limitation']}
