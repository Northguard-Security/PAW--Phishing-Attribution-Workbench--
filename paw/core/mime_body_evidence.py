"""Preserve bounded outer-body representations without interpreting/executing them."""
import hashlib
from pathlib import Path
import re


def preserve_body_parts(mime_result, original, evidence_dir):
    """Persist the already bounded analyze_mime result in a new case directory.

    Payload bytes are transfer-decoded/derived representations, not original
    MIME field spans. The unchanged input.eml remains the authoritative source.
    Text is separately derived using the recorded charset/replacement policy.
    """
    bodies = mime_result['body_parts']
    seen = set()
    for body in bodies:
        identifier = body['part_id']
        if not isinstance(identifier, str) or not re.fullmatch(r'0(?:\.[0-9]+)*', identifier) or identifier in seen:
            raise ValueError('Invalid or duplicate MIME body part identifier')
        seen.add(identifier)
    root = Path(evidence_dir)
    parts = []
    for body in bodies:
        metadata = body['metadata']
        data = body['payload']
        identifier = body['part_id']
        name = 'part-' + identifier.replace('.', '-')
        root.mkdir(parents=True, exist_ok=True)
        payload_path = root/(name+'.bin')
        # Never derive output paths from untrusted filenames or MIME headers.
        with payload_path.open('xb') as stream:
            stream.write(data)
        field = {'part_id':identifier, 'declared_mime':metadata['content_type'],
            'disposition':metadata['disposition'], 'content_id':metadata['content_id'],
            'size':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
            'byte_source':metadata['byte_source'], 'defects':list(metadata['defects']),
            'decoding':dict(metadata['decoding']),
            'payload_path':(Path(root.name)/payload_path.name).as_posix(),
            'payload_status':'captured', 'text_encoding':'utf-8',
            'text_path':None, 'text_sha256':None, 'text_size':None,
            'text_status':'unavailable', 'issues':[]}
        try:
            text_bytes = body['text'].encode('utf-8', errors='strict')
        except UnicodeEncodeError:
            # A derived string that cannot be represented as UTF-8 is not
            # silently rewritten. Its byte evidence still survives.
            field['issues'].append('derived_text_not_utf8_encodable')
        else:
            text_path = root/(name+'.txt')
            with text_path.open('xb') as stream:
                stream.write(text_bytes)
            field.update(text_path=(Path(root.name)/text_path.name).as_posix(),
                text_sha256=hashlib.sha256(text_bytes).hexdigest(), text_size=len(text_bytes),
                text_status='captured')
        if 'transfer_decoding' in metadata:
            field['transfer_decoding'] = dict(metadata['transfer_decoding'])
        field['status'] = 'partial' if (field['defects'] or field['decoding']['status'] != 'completed'
                                        or field.get('transfer_decoding', {}).get('status') == 'partial'
                                        or field['text_status'] != 'captured') else 'completed'
        parts.append(field)
    return {'schema_version':1, 'scope':'supported_outer_body_parts', 'verified':False,
        'source':{'path':'input.eml', 'sha256':hashlib.sha256(original).hexdigest()},
        'status':'partial' if any(p['status'] != 'completed' for p in parts) else 'completed',
        'parts':parts, 'part_count':len(parts), 'payload_bytes':sum(p['size'] for p in parts),
        'limitation':'Transfer-decoded/derived body bytes and per-part charset text; not exact MIME spans, authentication or execution. Original: input.eml. Attachments and unsupported types remain separate.',
        'limits':dict(mime_result['metadata']['limits'])}


def body_evidence_coverage(inventory):
    return {'status':inventory['status'], 'scope':inventory['scope'], 'verified':False,
        'artifact':'mime_body_evidence.json', 'part_count':inventory['part_count'],
        'payload_bytes':inventory['payload_bytes'],
        'partial_part_count':sum(p['status'] != 'completed' for p in inventory['parts']),
        'limitation':'Supported outer body representations preserved; attachments/unsupported types and full MIME coverage remain separate'}
