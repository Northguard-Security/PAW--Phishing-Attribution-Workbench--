
import email, re, os
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from .authentication import parse_authentication_results
from .mime_analysis import MimeLimits, MimeLimitExceeded
from .mailbox_domains import reply_domain_observation

def parse_eml_bytes(b: bytes):
    return _parse_msg_obj(parse_message_bytes(b))


def parse_message_bytes(raw, limits=MimeLimits()):
    if len(raw) > limits.max_input_bytes: raise MimeLimitExceeded('Input email byte limit exceeded')
    if not raw.strip(): raise ValueError('Empty email input')
    count = 0
    def bounded_factory(**kwargs):
        nonlocal count
        count += 1
        if count > limits.max_parts: raise MimeLimitExceeded('MIME part count limit exceeded during parsing')
        return EmailMessage(**kwargs)
    try:
        message = BytesParser(_class=bounded_factory, policy=policy.default).parsebytes(raw)
        # Retain the bounded wire source for checks that serialization can hide.
        message._paw_source_bytes = raw
        return message
    except RecursionError as exc:
        raise MimeLimitExceeded('MIME nesting exceeds parser capability') from exc

def parse_msg_bytes(b: bytes):
    raise RuntimeError('MSG analysis is unavailable until a validated conversion preserves transport headers and attachments; provide original EML')


def load_mail(path: str, limits=MimeLimits()):
    if os.path.splitext(path)[1].lower() == '.msg': parse_msg_bytes(b'')
    with open(path, 'rb') as stream:
        raw = stream.read(limits.max_input_bytes + 1)
    if len(raw) > limits.max_input_bytes: raise MimeLimitExceeded('Input email byte limit exceeded')
    msg = parse_message_bytes(raw, limits)
    return _parse_msg_obj(msg), msg, raw


def parse_mail(path: str):
    return load_mail(path)[0]


def _parse_msg_obj(msg):
    """Parse email.Message or extract_msg.Message object."""
    # Standard email.Message object
    hdr = msg._headers if hasattr(msg, "_headers") else list(msg.items())
    def get(h):
        v = msg.get(h)
        return v if v is not None else ""
    headers = {
        "from": get("From"),
        "reply_to": get("Reply-To") or "",
        "return_path": get("Return-Path") or "",
        "message_id": get("Message-ID") or "",
        "date": get("Date") or "",
        "subject": get("Subject") or ""
    }
    # Collect Authentication-Results (may have multiple)
    auth_res = msg.get_all("Authentication-Results") or []
    headers["authentication_results"] = [parse_authentication_results(str(raw), index) for index, raw in enumerate(auth_res)]
    headers["auth_results"] = _legacy_auth(headers["authentication_results"])
    
    # Parse ARC headers
    arc_seals = msg.get_all("ARC-Seal") or []
    arc_msgsigs = msg.get_all("ARC-Message-Signature") or []
    arc_authres = msg.get_all("ARC-Authentication-Results") or []
    headers["arc"] = {
        "seals": arc_seals,
        "message_signatures": arc_msgsigs,
        "auth_results": arc_authres
    }

    # Parse Received-SPF
    received_spf_raw = msg.get_all("Received-SPF") or []

    # Parse Received-SPF components
    received_spf_parsed = []
    for rspf in received_spf_raw:
        parsed = {"result": None, "helo": None, "client_ip": None}
        # Extract result
        m_result = re.match(r'\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b', str(rspf).lower())
        if m_result:
            parsed["result"] = m_result.group(1)
        # Extract client-ip
        m_client_ip = re.search(r'client-ip=([^\s;]+)', rspf.lower())
        if m_client_ip:
            parsed["client_ip"] = m_client_ip.group(1)
        # Extract helo
        m_helo = re.search(r'helo=([^\s;]+)', rspf.lower())
        if m_helo:
            parsed["helo"] = m_helo.group(1)
        received_spf_parsed.append(parsed)

    headers["received_spf"] = received_spf_parsed

    # Received lines (preserve order as in message - topmost is last hop)
    received = msg.get_all("Received") or []
    headers["received"] = received
    return _annotate(headers, msg)


def _legacy_auth(records):
    """Compatibility fields from one header; never merge unrelated receivers."""
    methods = records[0]['methods'] if len(records) == 1 and records[0]['status'] == 'parsed' else []
    def one(name):
        values = [method['result'] for method in methods if method['method'] == name]
        return values[0] if len(values) == 1 else None
    return {'spf': one('spf'), 'dmarc': one('dmarc'), 'dkim': [
        {'result': method['result'], 'd': method['properties'].get('header.d')}
        for method in methods if method['method'] == 'dkim']}


def _annotate(headers, msg):
    if hasattr(msg, 'get_all'):
        from_fields = msg.get_all('From') or []
        headers['from_header_count'] = len(from_fields)
        identity = {'status':'unavailable','scope':'single_ungrouped_mailbox',
                    'reason':'No From field','source':'message_headers','verification':'not_evaluated'}
        if len(from_fields) > 1:
            identity.update(status='unsupported',reason='Multiple From fields; no identity selected')
        elif from_fields:
            field = from_fields[0]
            if not hasattr(field,'addresses'):
                identity.update(status='not_evaluated',reason='Structured From parsing unavailable')
            elif field.defects:
                identity.update(status='partial',reason='From field has reported parsing defects')
            elif len(field.groups) != 1 or field.groups[0].display_name is not None or len(field.addresses) != 1:
                identity.update(status='unsupported',reason='Grouped or multiple mailboxes outside supported identity scope')
            elif not field.addresses[0].username or not field.addresses[0].domain:
                identity.update(status='unsupported',reason='Complete mailbox username/domain unavailable')
            else:
                identity.update(status='parsed',reason='One ungrouped mailbox parsed; identity not verified')
        headers['from_identity'] = identity
        headers['return_path_header_count'] = len(msg.get_all('Return-Path') or [])
        headers['dkim_signature_present'] = bool(msg.get_all('DKIM-Signature'))
        headers['header_defects'] = [str(defect) for defect in msg.defects]
        # Message-level defects do not include each structured field's defects.
        # Preserve occurrences for identity/date/subject fields, without turning
        # malformed/unavailable observations into authentication or risk points.
        headers['header_field_defects'] = []
        for field in ('From','Reply-To','Return-Path','Date','Subject'):
            for index, value in enumerate(msg.get_all(field) or []):
                for defect in getattr(value,'defects',()):
                    kind = type(defect).__name__
                    headers['header_field_defects'].append({
                        'field':field,'header_index':index,'type':kind,
                        'description':str(defect),'source':'message_headers'})
                    headers['header_defects'].append(f'{field}[{index}]: {kind}: {defect}')
        reply_fields = msg.get_all('Reply-To') or []
        headers['reply_to_header_count'] = len(reply_fields)
        headers['reply_to_domain'] = reply_domain_observation(
            reply_fields[0] if reply_fields else '',count=len(reply_fields))
    else:
        headers['from_header_count'] = None
        headers['from_identity'] = {'status':'not_evaluated','scope':'single_ungrouped_mailbox',
                                    'reason':'Structured From parsing unavailable',
                                    'source':'message_headers','verification':'not_evaluated'}
        headers['return_path_header_count'] = None
        headers['dkim_signature_present'] = None
        headers['header_defects'] = ['MSG transport header completeness not validated']
        headers['header_field_defects'] = []
        headers['reply_to_header_count'] = None
        headers['reply_to_domain'] = reply_domain_observation('',count=None)
    return headers
