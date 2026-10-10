"""Attachment evidence metadata. No execution, archive extraction or AV verdict."""
from collections import Counter
import hashlib
import io
import math
from pathlib import Path, PurePosixPath
import zipfile
import blake3
from .mime_analysis import analyze_mime


def _calculate_entropy(data):
    if not data: return 0.0
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in Counter(data).values())


def archive_inventory(data, max_entries=1000, max_total_size=100 * 1024 * 1024):
    if not data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
        return {'status':'not_evaluated', 'reason':'Not a ZIP container'}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > max_entries:
                return {'status':'limited', 'reason':'ZIP entry count exceeds limit', 'entry_count':len(entries)}
            total = sum(entry.file_size for entry in entries)
            inventory = []
            for entry in entries:
                name = entry.filename.replace('\\', '/')
                path = PurePosixPath(name)
                unsafe = path.is_absolute() or '..' in path.parts or ':' in name or '\x00' in name
                inventory.append({'name':entry.filename, 'declared_size':entry.file_size,
                    'compressed_size':entry.compress_size, 'encrypted':bool(entry.flag_bits & 1),
                    'unsafe_extraction_path':unsafe})
            return {'status':'limited' if total > max_total_size else 'metadata_only',
                'entries':inventory, 'entry_count':len(entries), 'declared_total_size':total,
                'macro_container_entries':[entry.filename for entry in entries if entry.filename.lower().endswith('vbaproject.bin')],
                'reason':'Declared archive expansion exceeds limit' if total > max_total_size else 'Members not decompressed or analyzed',
                'limits':{'max_entries':max_entries,'max_declared_total_size':max_total_size}}
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return {'status':'error', 'reason':type(exc).__name__}


def _analyze_attachment(att_data, filename, declared_mime='application/octet-stream'):
    return {'filename':filename or '(unnamed)', 'size':len(att_data),
        'sha256':hashlib.sha256(att_data).hexdigest(), 'blake3':blake3.blake3(att_data).hexdigest(),
        'mime':declared_mime, 'declared_mime':declared_mime, 'detected_mime':None,
        'mime_detection':{'status':'not_evaluated', 'reason':'Declared MIME is not independent type detection'},
        'entropy':_calculate_entropy(att_data), 'ole_macro':None,
        'macro_analysis':{'status':'not_evaluated', 'reason':'No validated macro analysis performed'},
        'archive':archive_inventory(att_data),
        'status':'metadata_only', 'assessment_status':'partial', 'risk_score':None, 'risk_level':'not_evaluated',
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
