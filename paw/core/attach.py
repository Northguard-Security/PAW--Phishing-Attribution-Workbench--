"""Attachment evidence metadata. No execution, archive extraction or AV verdict."""
from collections import Counter
import hashlib
import io
import math
from pathlib import Path, PurePosixPath
import struct
import zipfile
import zlib
import blake3
from .mime_analysis import analyze_mime


def _calculate_entropy(data):
    if not data: return 0.0
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in Counter(data).values())


def _unsafe_path(name):
    name = name.replace('\\', '/')
    path = PurePosixPath(name)
    return path.is_absolute() or '..' in path.parts or ':' in name or '\x00' in name


def _unicode_path_check(entry):
    """Inspect central-directory declarations before ZipInfo NUL sanitization.

    Keep only counts/flags, not an unbounded collection of extra-field names.
    CRC matching binds to the declared legacy spelling, not to authenticity.
    """
    result = {'status':'completed', 'scope':'crc_matched_version_1_unicode_path_extra_values',
        'field_count':0, 'matched_name_count':0, 'ignored_field_count':0,
        'unsafe_name_count':0, 'nul_name_count':0, 'issues':[]}
    legacy = entry.orig_filename.encode('utf-8' if entry.flag_bits & 0x800 else 'cp437')
    crc = zlib.crc32(legacy)
    extra, offset = entry.extra, 0
    while offset+4 <= len(extra):
        tag, length = struct.unpack_from('<HH',extra,offset)
        offset += 4
        if offset+length > len(extra):
            result['issues'].append('malformed_extra_field'); break
        data = extra[offset:offset+length]; offset += length
        if tag != 0x7075: continue
        result['field_count'] += 1
        if len(data) < 5:
            issue = 'malformed_unicode_path_extra'
        elif data[0] != 1 or struct.unpack_from('<I',data,1)[0] != crc:
            result['ignored_field_count'] += 1; continue
        else:
            try:
                name = data[5:].decode('utf-8')
            except UnicodeDecodeError:
                issue = 'invalid_unicode_path_utf8'
            else:
                result['matched_name_count'] += 1
                result['unsafe_name_count'] += _unsafe_path(name)
                result['nul_name_count'] += '\x00' in name
                continue
        if issue not in result['issues']: result['issues'].append(issue)
    if result['issues']: result['status'] = 'not_evaluated'
    return result


def archive_inventory(data, max_entries=1000, max_total_size=100 * 1024 * 1024,
                      max_name_bytes=4096, max_total_name_bytes=262144):
    for value in (max_entries, max_total_size, max_name_bytes, max_total_name_bytes):
        if type(value) is not int or value <= 0:
            raise ValueError('Archive inventory limits must be positive integers')
    if not data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
        return {'status':'not_evaluated', 'reason':'No supported ZIP prefix; ZIP membership not verified'}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            total = sum(entry.file_size for entry in entries)
            inventory, issues, name_bytes = [], [], 0
            if len(entries) > max_entries: issues.append('entry_count_limit')
            if total > max_total_size: issues.append('declared_total_size_limit')
            for index, entry in enumerate(entries[:max_entries]):
                # NUL/separator normalization and Unicode extra fields can make
                # these parser views differ. Bound and inspect both observations.
                original = entry.orig_filename
                views = {original, entry.filename}
                unicode_check = _unicode_path_check(entry)
                unsafe = any(_unsafe_path(view) for view in views) or bool(unicode_check['unsafe_name_count'])
                if unicode_check['status'] != 'completed':
                    if 'unicode_path_check_unavailable' not in issues: issues.append('unicode_path_check_unavailable')
                    if not unsafe: unsafe = None
                size = len(original.encode('utf-8'))
                parser_size = len(entry.filename.encode('utf-8'))
                retained_size = sum(len(view.encode('utf-8')) for view in views)
                name_issue = ('entry_name_size_limit' if max(size, parser_size) > max_name_bytes else
                    'entry_name_byte_budget' if name_bytes+retained_size > max_total_name_bytes else None)
                if name_issue:
                    if name_issue not in issues: issues.append(name_issue)
                else:
                    name_bytes += retained_size
                inventory.append({'entry_index':index,
                    'name':None if name_issue else entry.filename,
                    'original_name':None if name_issue else original,
                    'name_status':'limited' if name_issue else 'captured',
                    'name_issues':[name_issue] if name_issue else [],
                    'name_utf8_bytes':size, 'parser_name_utf8_bytes':parser_size,
                    'name_normalized':entry.filename != original,
                    'declared_size':entry.file_size,
                    'compressed_size':entry.compress_size, 'encrypted':bool(entry.flag_bits & 1),
                    'unsafe_extraction_path':unsafe, 'unicode_path_check':unicode_check})
            limited = any(issue != 'unicode_path_check_unavailable' for issue in issues)
            return {'status':'limited' if limited else 'partial' if issues else 'metadata_only',
                'entries':inventory, 'entry_count':len(entries), 'declared_total_size':total,
                'inventoried_entry_count':len(inventory), 'omitted_entry_count':len(entries)-len(inventory),
                'limited_name_count':sum(entry['name_status'] != 'captured' for entry in inventory),
                'captured_name_utf8_bytes':name_bytes, 'issues':issues,
                'macro_container_entries':[entry['name'] for entry in inventory
                    if entry['name'] is not None and entry['name'].lower().endswith('vbaproject.bin')],
                'macro_container_entries_scope':'inventoried_entries_with_retained_parser_names',
                'verified':False, 'scope':'parser_decoded_zip_central_directory_metadata',
                'reason':'Archive metadata incomplete: '+', '.join(issues) if issues else 'Members not decompressed or analyzed',
                'limitation':'Parser-decoded central-directory declarations, not original name byte spans, member integrity, macro validation or malware analysis',
                'limits':{'max_entries':max_entries,'max_declared_total_size':max_total_size,
                    'max_name_utf8_bytes':max_name_bytes,'max_total_name_utf8_bytes':max_total_name_bytes}}
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as exc:
        return {'status':'error', 'reason':type(exc).__name__}


def _analyze_attachment(att_data, filename, declared_mime='application/octet-stream'):
    archive = archive_inventory(att_data)
    return {'filename':filename or '(unnamed)', 'size':len(att_data),
        'sha256':hashlib.sha256(att_data).hexdigest(), 'blake3':blake3.blake3(att_data).hexdigest(),
        'mime':declared_mime, 'declared_mime':declared_mime, 'detected_mime':None,
        'mime_detection':{'status':'not_evaluated', 'reason':'Declared MIME is not independent type detection'},
        'entropy':_calculate_entropy(att_data), 'ole_macro':None,
        'macro_analysis':{'status':'not_evaluated', 'reason':'No validated macro analysis performed'},
        'archive':archive,
        'status':'partial' if archive['status'] in {'limited','error','partial'} else 'metadata_only',
        'assessment_status':'partial', 'risk_score':None, 'risk_level':'not_evaluated',
        'malware_analysis':{'status':'not_evaluated', 'reason':'Metadata and hashes do not establish absence of malware'}}


def scan_attachments(msg_obj, mime_result=None, evidence_dir=None):
    mime_result = mime_result if mime_result is not None else analyze_mime(msg_obj)
    output = []
    for attachment in mime_result['attachments']:
        data, part_id = attachment['payload'], attachment['part_id']
        item = _analyze_attachment(data, attachment['filename'], attachment['declared_mime'])
        item.update(part_id=part_id, disposition=attachment['disposition'], byte_source=attachment['byte_source'],
                    decoding_defects=attachment['defects'])
        if attachment['defects']: item['status'] = 'partial'
        if 'transfer_decoding' in attachment:
            item['transfer_decoding'] = dict(attachment['transfer_decoding'])
            item['status'] = 'partial'
        if evidence_dir is not None:
            root = Path(evidence_dir)
            root.mkdir(parents=True, exist_ok=True)
            # Never use the untrusted MIME filename as a filesystem path.
            path = root / ('part-' + part_id.replace('.', '-') + '-' + item['sha256'] + '.bin')
            path.write_bytes(data)
            item['evidence_path'] = str(Path(root.name) / path.name).replace('\\', '/')
        output.append(item)
    return output
