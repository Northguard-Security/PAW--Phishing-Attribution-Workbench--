"""Bounded offline MIME extraction; original email bytes remain the evidence."""
from dataclasses import dataclass
from copy import copy
import hashlib
from html.parser import HTMLParser
import re


@dataclass(frozen=True)
class MimeLimits:
    max_input_bytes: int = 25 * 1024 * 1024
    max_parts: int = 500
    max_depth: int = 30
    max_decoded_bytes: int = 20 * 1024 * 1024
    max_text_bytes: int = 2 * 1024 * 1024


class MimeLimitExceeded(ValueError):
    pass


def iter_parts(message, limits=MimeLimits()):
    """Do not interpret attached/embedded emails as the outer message body."""
    stack, count = [(message, '0', 0, False)], 0
    while stack:
        part, path, depth, attached_parent = stack.pop()
        count += 1
        if count > limits.max_parts or depth > limits.max_depth:
            raise MimeLimitExceeded('MIME part/depth limit exceeded')
        attached = attached_parent or part.get_content_disposition() == 'attachment' or bool(part.get_filename())
        yield part, path, attached
        # Embedded message is one attachment, not another transmitting header chain.
        if part.get_content_maintype() == 'message': continue
        payload = part.get_payload()
        if isinstance(payload, list):
            stack.extend((child, f'{path}.{index}', depth + 1, attached)
                         for index, child in reversed(list(enumerate(payload))))


def uuencode_has_end(encoded):
    """Check the terminator of the first begin block selected by the stdlib.

    A terminator in the preamble or an ignored invalid-mode block cannot
    establish completion of the decoded block. This does not decode data.
    """
    lines = iter(encoded.splitlines())
    for line in lines:
        if line.startswith(b'begin '):
            mode = line[6:].partition(b' ')[0]
            try:
                int(mode, base=8)
            except ValueError:
                continue
            break
    else:
        return False
    return any(line.strip(b' \t\r\n\f') == b'end' for line in lines)


def quoted_printable_is_complete(encoded):
    """Check RFC 2045 syntax that the stdlib decodes without recovery.

    Preserve its output even for malformed/noncanonical input. Transport
    padding is legal to receive, but the stdlib retains it (and fails to
    remove padded soft breaks), so that interpretation remains partial too.
    This validates bytes; it neither repairs nor decodes them.
    """
    hex_digits = b'0123456789ABCDEF'
    for line in encoded.splitlines(keepends=True):
        newline = line.endswith(b'\r\n')
        if newline:
            line = line[:-2]
        elif line.endswith((b'\r', b'\n')):
            return False
        if len(line) > 76 or line.endswith((b' ', b'\t')) or re.search(rb'[^\t\x20-\x7e]', line):
            return False
        position = 0
        while (position := line.find(b'=', position)) != -1:
            if position + 2 < len(line) and line[position+1] in hex_digits and line[position+2] in hex_digits:
                position += 3
            elif position == len(line) - 1 and newline:
                break
            else:
                return False
    return True


def identity_transfer_is_valid(payload, cte):
    """Validate RFC 2045 sections 2.7-2.9 without transforming bytes.

    An absent declaration defaults to 7bit (section 6.1). Both line-oriented
    domains exclude NUL, bare CR/LF and lines over 998 octets; 7bit also excludes
    high octets. Binary has no octet or line constraints.
    """
    if cte == 'binary':
        return True
    if b'\x00' in payload or re.search(rb'\r(?!\n)|(?<!\r)\n', payload):
        return False
    if cte == '7bit' and re.search(rb'[\x80-\xff]', payload):
        return False
    return all(len(line) <= 998 for line in payload.split(b'\r\n'))


def embedded_wire_payloads(message, limits):
    """Locate embedded attachment bodies in the bounded original wire source.

    Follow only multipart framing matching the existing parser tree. Never
    reconstruct a wire payload from serialization or descend into its embedded
    message. Ambiguous/missing framing leaves the transfer check unavailable.
    Offsets and delimiter counts are bounded; no per-line list or second decoder.
    """
    raw = getattr(message, '_paw_source_bytes', None)
    if not isinstance(raw, bytes):
        return {}
    if len(raw) > limits.max_input_bytes:
        raise MimeLimitExceeded('Input email byte limit exceeded')
    bodies = {}
    stack = [(message, 0, len(raw))]
    newlines = re.compile(rb'\r\n|\r|\n')
    while stack:
        part, start, end = stack.pop()
        # The parser may have promoted a malformed header line into the body
        # before any blank separator. A later separator cannot locate that body.
        if any(type(d).__name__ == 'MissingHeaderBodySeparatorDefect' for d in part.defects):
            continue
        previous = start
        for newline in newlines.finditer(raw, start, end):
            if newline.start() == previous:
                body_start = newline.end()
                break
            previous = newline.end()
        else:
            continue
        if part.get_content_maintype() == 'message':
            bodies[id(part)] = raw[body_start:end]
            continue
        children = part.get_payload()
        if part.get_content_maintype() != 'multipart' or not isinstance(children, list):
            continue
        boundary = part.get_boundary()
        if not boundary:
            continue
        try:
            marker = boundary.encode('ascii')
        except UnicodeError:
            continue
        if not re.fullmatch(rb"[0-9A-Za-z'()+_,./:=? -]{1,70}", marker) or marker.endswith(b' '):
            continue
        delimiters = re.compile(rb'(?:\A|(?<=\r)|(?<=\n))--'+re.escape(marker)
                                +rb'(?P<close>--)?[ \t]*(?:\r\n|\r|\n|\Z)')
        spans, child_start, closed = [], None, False
        for delimiter in delimiters.finditer(raw, body_start, end):
            if child_start is not None:
                child_end = delimiter.start()
                if raw[max(child_start, child_end-2):child_end] == b'\r\n':
                    child_end -= 2
                elif child_end > child_start and raw[child_end-1:child_end] in (b'\r', b'\n'):
                    child_end -= 1
                spans.append((child_start, child_end))
                if len(spans) > len(children):
                    break
            if delimiter.group('close'):
                closed = True
                break
            child_start = delimiter.end()
        if closed and len(spans) == len(children):
            stack.extend((child, a, b) for child, (a, b) in zip(children, spans))
    return bodies


def decoded_payload(part, embedded_wire=None):
    declarations = part.get_all('Content-Transfer-Encoding', [])
    header = part.get('Content-Transfer-Encoding', '')
    cte = getattr(header, 'cte', str(header).strip().lower()) if str(header).strip() else ''
    if part.get_content_maintype() == 'message':
        payload = part.get_payload()
        if isinstance(payload, list):
            derived = b'\r\n'.join(child.as_bytes() for child in payload)
            if (part.get_content_type() != 'message/rfc822' or len(declarations) > 1
                    or (declarations and cte not in {'7bit', '8bit', 'binary'}) or embedded_wire is None):
                return derived, 'derived_embedded_message_transfer_unavailable'
            if not identity_transfer_is_valid(embedded_wire, cte if declarations else '7bit'):
                return derived, 'derived_embedded_message_invalid_transfer_domain'
            return derived, 'derived_embedded_message_serialization'
    payload = part.get_payload(decode=True)
    if payload is None:
        if part.is_multipart(): return None, 'container'
        raw = part.get_payload()
        if isinstance(raw, str): return raw.encode('utf-8', errors='surrogateescape'), 'fallback_utf8_serialization'
        return b'', 'empty'
    # The stdlib selects the first occurrence. Retain its representation, but
    # don't claim an unambiguous successful transfer decoding for duplicates.
    if len(declarations) > 1:
        return payload, 'derived_first_transfer_encoding'
    identity = {'7bit', '8bit', 'binary'}
    uuencodings = {'x-uuencode', 'uuencode', 'uue', 'x-uue'}
    if declarations and cte not in identity | uuencodings | {'base64', 'quoted-printable'}:
        return payload, 'undecoded_unsupported_transfer_encoding'
    if not declarations or cte in identity:
        if not identity_transfer_is_valid(payload, cte if declarations else '7bit'):
            return payload, 'identity_bytes_invalid_transfer_domain'
    if cte == 'base64' and any(type(d).__name__ == 'InvalidBase64LengthDefect' for d in part.defects):
        return payload, 'undecoded_failed_transfer_encoding'
    if cte in uuencodings | {'quoted-printable'}:
        # Inspect transfer syntax/fallback using the same parser byte conversion
        # without charset replacement. Don't guess an alternative encoding.
        identity_part = copy(part)
        del identity_part['Content-Transfer-Encoding']
        encoded = identity_part.get_payload(decode=True)
        if cte == 'quoted-printable':
            if not quoted_printable_is_complete(encoded):
                return payload, 'transfer_decoded_partial_syntax'
        elif payload == encoded:
            return payload, 'undecoded_failed_transfer_encoding'
        elif not uuencode_has_end(encoded):
            return payload, 'transfer_decoded_incomplete_framing'
    return payload, 'transfer_decoded_bytes'


TRANSFER_PARTIAL_REASONS = {
    'derived_embedded_message_invalid_transfer_domain': 'Original embedded-message bytes violate the declared/default identity transfer domain; derived serialization retained',
    'derived_embedded_message_transfer_unavailable': 'Embedded-message wire mapping or unambiguous supported transfer interpretation unavailable; derived serialization retained',
    'identity_bytes_invalid_transfer_domain': 'Payload violates declared 7bit/8bit transfer domain (absent declaration defaults to 7bit); unchanged parser bytes retained',
    'undecoded_unsupported_transfer_encoding': 'Unsupported or empty declared transfer encoding; parser payload retained undecoded',
    'undecoded_failed_transfer_encoding': 'Transfer decoder returned undecoded parser payload',
    'transfer_decoded_incomplete_framing': 'Uuencode stream missing end terminator; recovered decoded bytes retained',
    'transfer_decoded_partial_syntax': 'Quoted-printable syntax is malformed/noncanonical or has unsupported transport padding; parser-decoded bytes retained',
    'derived_first_transfer_encoding': 'Duplicate transfer encoding declarations; parser used the first occurrence',
    'fallback_utf8_serialization': 'Parser payload serialized as UTF-8; transfer decoding unavailable',
}


def part_defects(part):
    defects = [type(defect).__name__ for defect in part.defects]
    for _, header in part.items():
        defects.extend(type(defect).__name__ for defect in getattr(header, 'defects', ()))
    return list(dict.fromkeys(defects))


def decode_text(part, payload):
    charset = part.get_content_charset() or 'us-ascii'
    try:
        return payload.decode(charset, errors='strict'), {'declared_charset': part.get_content_charset(),
            'used_charset': charset, 'status': 'completed', 'replacement_used': False}
    except (LookupError, UnicodeError):
        # Preserve raw bytes elsewhere; replacements are explicit, never silently dropped.
        return payload.decode('utf-8', errors='replace'), {'declared_charset': part.get_content_charset(),
            'used_charset': 'utf-8', 'status': 'partial', 'replacement_used': True,
            'reason': 'Unknown charset or bytes invalid for declared/default charset'}


def extract_urls(text):
    return list(dict.fromkeys(re.findall(r'https?://[^\s<>"\']+', text, flags=re.IGNORECASE)))


class HtmlEvidenceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls, self.text, self.excluded = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style'}: self.excluded += 1
        for name, value in attrs:
            if value and name in {'href', 'src', 'action', 'formaction', 'poster', 'srcset', 'data'}:
                self.urls.extend(extract_urls(value))

    def handle_endtag(self, tag):
        if tag in {'script', 'style'} and self.excluded: self.excluded -= 1
        if tag in {'p', 'div', 'br', 'li'}: self.text.append('\n')

    def handle_data(self, value):
        if not self.excluded: self.text.append(value)


def analyze_mime(message, limits=MimeLimits()):
    # Validate embedded trees too, before serializing them as attachment evidence.
    stack, count, has_embedded = [(message, 0)], 0, False
    while stack:
        part, depth = stack.pop()
        count += 1
        if count > limits.max_parts or depth > limits.max_depth:
            raise MimeLimitExceeded('MIME part/depth limit exceeded')
        payload = part.get_payload()
        has_embedded |= part.get_content_maintype() == 'message' and isinstance(payload, list)
        if isinstance(payload, list): stack.extend((child, depth + 1) for child in payload)
    wire_payloads = embedded_wire_payloads(message, limits) if has_embedded else {}
    parts, text, html, javascript, urls, attachments, issues = [], [], [], [], [], [], []
    body_parts = []
    decoded_total, text_total = 0, 0
    for part, path, attached in iter_parts(message, limits):
        content_type = part.get_content_type()
        item = {'part_id': path, 'content_type': content_type,
                'disposition': part.get_content_disposition(), 'filename': part.get_filename(),
                'content_id': str(part.get('Content-ID') or ''), 'attached': attached}
        container = part.is_multipart() and part.get_content_maintype() == 'multipart'
        if container:
            item['defects'] = part_defects(part)
            parts.append(item)
            if item['defects']: issues.append({'part_id':path, 'defects':item['defects']})
            continue
        payload, byte_source = decoded_payload(part, wire_payloads.get(id(part)))
        if payload is None: payload = b''
        decoded_total += len(payload)
        if decoded_total > limits.max_decoded_bytes:
            raise MimeLimitExceeded('Total decoded MIME byte limit exceeded')
        item.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest(), byte_source=byte_source)
        if byte_source in TRANSFER_PARTIAL_REASONS:
            item['transfer_decoding'] = {'status':'partial',
                'declared_encodings':[str(value) for value in part.get_all('Content-Transfer-Encoding', [])],
                'reason':TRANSFER_PARTIAL_REASONS[byte_source]}
            issues.append({'part_id':path, 'transfer_decoding':dict(item['transfer_decoding'])})
        # Transfer decoding can add base64 defects, so inspect after decoding.
        item['defects'] = part_defects(part)
        if item['defects']: issues.append({'part_id':path, 'defects':item['defects']})
        supported_text = content_type in {'text/plain', 'text/html', 'text/javascript'}
        is_attachment = attached or not supported_text
        if is_attachment:
            item['attached'] = True
            attachments.append({'part':part, 'part_id':path, 'payload':payload, 'byte_source':byte_source,
                'defects':item['defects'], 'declared_mime':content_type,
                'filename':part.get_filename(), 'disposition':part.get_content_disposition()})
            if 'transfer_decoding' in item:
                attachments[-1]['transfer_decoding'] = dict(item['transfer_decoding'])
            if not attached:
                item['content_analysis'] = 'not_evaluated'
                issues.append({'part_id':path, 'reason':'Non-body MIME content preserved; content analysis not evaluated'})
        elif supported_text:
            text_total += len(payload)
            if text_total > limits.max_text_bytes: raise MimeLimitExceeded('Text analysis byte limit exceeded')
            value, decoding = decode_text(part, payload)
            item['decoding'] = decoding
            # Retain the per-part bytes before charset replacement and before
            # independent text/HTML/JS representations are joined for analysis.
            body_parts.append({'metadata':dict(item), 'payload':payload, 'text':value,
                               'part_id':path})
            if decoding['status'] != 'completed': issues.append({'part_id':path, 'decoding':decoding})
            if content_type == 'text/html':
                parser = HtmlEvidenceParser()
                parser.feed(value)
                parser.close()
                visible = ''.join(parser.text)
                html.append(value)
                text.append(visible)
                urls.extend(parser.urls + extract_urls(visible))
            elif content_type == 'text/javascript':
                javascript.append(value)
                urls.extend(extract_urls(value))
            else:
                text.append(value)
                urls.extend(extract_urls(value))
        parts.append(item)
    return {'body_text':'\n'.join(text), 'body_parts':body_parts,
            'html':'\n'.join(html), 'html_parts':html,
            'javascript':'\n'.join(javascript),
            'urls':list(dict.fromkeys(urls)), 'attachments':attachments,
            'metadata':{'status':'partial' if issues else 'completed', 'parts':parts, 'issues':issues,
                'decoded_bytes':decoded_total, 'text_bytes':text_total,
                'limits':limits.__dict__, 'source':'MIME parts of original email',
                'limitation':'Decoded/embedded representations do not replace original input bytes'}}
