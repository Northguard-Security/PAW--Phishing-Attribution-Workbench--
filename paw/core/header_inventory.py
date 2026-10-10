"""Bounded top-level header observations from the existing email parser.

Parser raw values are not complete field byte spans: the parser removes the
colon, initial whitespace and final line endings. input.eml is the exact source.
The caller supplies that unchanged source and its freshly parsed message.
"""
import base64
from collections import Counter
from dataclasses import dataclass
import hashlib
from itertools import islice


@dataclass(frozen=True)
class HeaderInventoryLimits:
    max_fields: int = 1024
    max_name_bytes: int = 256
    max_value_bytes: int = 16384
    max_raw_bytes: int = 262144


def _defects(values):
    return [{'type':type(value).__name__, 'description':str(value)[:256]
             .encode('utf-8', 'replace').decode('utf-8')} for value in islice(values, 16)]


def inventory_headers(message, original, limits=HeaderInventoryLimits()):
    """Observe parser-recognized outer fields only; never verify their claims."""
    for value in vars(limits).values():
        if type(value) is not int or value <= 0:
            raise ValueError('Header inventory limits must be positive integers')
    source = {'path':'input.eml', 'sha256':hashlib.sha256(original).hexdigest()}
    return _inventory_headers(message, source, limits, 'parser_recognized_top_level_headers')


def _inventory_headers(message, source, limits, scope, parsed_budget=None):
    """Shared field capture. Internal callers supply validated remaining budgets.

    Zero remaining field/raw budgets retain counts and explicit omissions; the
    public top-level API still requires positive limits and keeps its schema.
    """
    parsed_bytes = 0
    total = len(message)
    result = {'schema_version':1, 'scope':scope,
        'verified':False, 'source':dict(source),
        'raw_value_encoding':'base64 of parser ASCII/surrogateescape value octets',
        'raw_value_limitation':'Not complete field byte spans; parser strips initial whitespace and final line endings. Exact original: input.eml.',
        'parsed_value_source':'email policy header_fetch_parse; derived, unverified view',
        'limits':dict(vars(limits)), 'total_field_count':total, 'fields':[],
        'omitted_field_count':max(0,total-limits.max_fields), 'limited_field_count':0,
        'captured_raw_bytes':0, 'message_defects':_defects(message.defects),
        'message_defect_count':len(message.defects), 'issues':[]}
    counts = Counter()
    if result['omitted_field_count']:
        result['issues'].append('field_count_limit')
    for index, (name, value) in enumerate(islice(message.raw_items(), limits.max_fields)):
        field = {'header_index':index, 'name':None, 'normalized_name':None,
            'occurrence_index':None, 'raw_status':'limited', 'raw_value_base64':None,
            'parsed_status':'not_evaluated', 'parsed_value':None, 'defects':[],
            'defect_count':0, 'issues':[]}
        result['fields'].append(field)
        if len(name) > limits.max_name_bytes:
            field['issues'].append('name_size_limit')
        else:
            try:
                name_bytes = name.encode('ascii')
                value_size = len(value)
                normalized = name.lower()
                field.update(name=name, normalized_name=normalized,
                    occurrence_index=counts[normalized], raw_value_character_count=value_size)
                counts[normalized] += 1
                if value_size > limits.max_value_bytes:
                    field['issues'].append('value_size_limit')
                elif result['captured_raw_bytes']+len(name_bytes)+value_size > limits.max_raw_bytes:
                    field['issues'].append('raw_byte_budget')
                else:
                    # BytesParser uses ASCII with surrogateescape: do not UTF-8
                    # re-encode replacement glyphs and call them original bytes.
                    octets = value.encode('ascii', 'surrogateescape')
                    field.update(raw_status='captured', raw_value_base64=base64.b64encode(octets).decode('ascii'))
                    result['captured_raw_bytes'] += len(name_bytes)+len(octets)
                    non_ascii = not octets.isascii()
                    if non_ascii:
                        field['issues'].append('non_ascii_parser_source_octets')
                    try:
                        parsed = message.policy.header_fetch_parse(name, value)
                        defects = getattr(parsed, 'defects', ())
                        field.update(defects=_defects(defects), defect_count=len(defects))
                        text = str(parsed)
                        if len(text) > limits.max_value_bytes:
                            field['parsed_status'] = 'limited'
                            field['issues'].append('parsed_value_size_limit')
                        else:
                            field['parsed_value'] = text.encode('utf-8', 'replace').decode('utf-8')
                            replaced = field['parsed_value'] != text
                            field['parsed_status'] = 'partial' if defects or replaced or non_ascii else 'completed'
                            if replaced:
                                field['issues'].append('parsed_value_unencodable_characters')
                            size = len(field['parsed_value'].encode('utf-8'))
                            if parsed_budget is not None and parsed_bytes + size > parsed_budget:
                                field.update(parsed_value=None, parsed_status='limited')
                                field['issues'].append('parsed_byte_budget')
                            else:
                                parsed_bytes += size
                    except Exception as exc:
                        # An unsupported/malformed derived field must not erase
                        # its raw observation or fail the whole analysis.
                        field['parsed_status'] = 'unavailable'
                        field['issues'].append('field_parse_error:'+type(exc).__name__)
            except UnicodeEncodeError:
                field['raw_status'] = 'unavailable'
                field['issues'].append('parser_source_octets_unavailable')
        if field['raw_status'] != 'captured' or field['parsed_status'] == 'limited':
            result['limited_field_count'] += 1
    result['inventoried_field_count'] = len(result['fields'])
    # These two counts cover only retained names, never omitted/oversized ones.
    result['distinct_name_count'] = len(counts)
    result['duplicate_occurrence_count'] = sum(count-1 for count in counts.values())
    result['name_count_scope'] = 'inventoried_fields_with_retained_names'
    result['status'] = 'partial' if (result['issues'] or result['message_defect_count'] or
        any(f['raw_status'] != 'captured' or f['parsed_status'] != 'completed' for f in result['fields'])) else 'completed'
    return result


def inventory_coverage(inventory):
    """Small coverage record; values remain in the separate sealed artifact."""
    keys = ('status','scope','verified','total_field_count','inventoried_field_count',
        'omitted_field_count','limited_field_count','message_defect_count')
    return {**{key:inventory[key] for key in keys}, 'artifact':'header_inventory.json',
        'limitation':'Parser observations and derived values, not authenticity. Exact original: input.eml.'}
