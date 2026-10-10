
import os, json, uuid, shutil, hashlib, time, ipaddress, re
from ..util.timeutil import utc_now_iso
from ..util.hashutil import blake3_hex, file_blake3_hex
from ..util.fsutil import ensure_dir, write_json, write_text, sanitize_case_id, read_json
from .parser_mail import parse_mail, load_mail
from .mime_analysis import analyze_mime
from .header_inventory import inventory_headers, inventory_coverage
from .mime_header_inventory import inventory_mime_headers, mime_header_coverage
from .mime_body_evidence import preserve_body_parts, body_evidence_coverage
from .evidence import seal_case
from .runtime import mark_stage, read_progress
from .received import normalize_received
from .auth import infer_alignment, authentication_report
from .dkim_offline import verify_dkim_offline
from .dkim_keys import parse_key_evidence
from .profiler import ip_rdap, domain_rdap, nrd_days, observe_domain_age
from .scoring import score_case, finalize_score, validate_deobfuscation_weight
from .network_policy import enforce_trace_policy, network_allowed, violations
from .batch import BatchAnalysisError, select_inputs
from ..deobfuscate.core import DeobfuscationEngine

# Rich imports for beautiful terminal output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn

def check_domain_reputation(domain):
    """Check domain reputation using various sources."""
    if not domain:
        return {"score": 0, "category": "unknown", "sources": []}
    
    reputation = {"score": 0, "category": "unknown", "sources": []}
    
    # Check for suspicious keywords in domain
    suspicious_keywords = [
        'secure', 'login', 'verify', 'account', 'update', 'confirm', 'alert', 'warning',
        'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'support',
        'notification', 'service', 'help', 'contact', 'admin'
    ]
    
    domain_lower = domain.lower()
    for keyword in suspicious_keywords:
        if keyword in domain_lower:
            reputation["score"] += 1
            reputation["sources"].append(f"keyword:{keyword}")
    
    # Check for numbers in domain (often used in phishing)
    import re
    if re.search(r'\d', domain):
        reputation["score"] += 1
        reputation["sources"].append("contains_numbers")
    
    # Check domain age (very new domains are suspicious)
    try:
        from .profiler import domain_rdap
        rdap = domain_rdap(domain)
        created = rdap.get("created")
        if created:
            age_days = nrd_days(created)
            
            if age_days is not None and age_days < 30:
                reputation["score"] += 5  # Very suspicious
                reputation["sources"].append(f"very_new_domain:{age_days}d")
            elif age_days is not None and age_days < 365:
                reputation["score"] += 2  # Moderately suspicious
                reputation["sources"].append(f"new_domain:{age_days}d")
    except:
        pass
    
    # Determine category based on score
    if reputation["score"] >= 5:
        reputation["category"] = "high_risk"
    elif reputation["score"] >= 2:
        reputation["category"] = "medium_risk"
    elif reputation["score"] > 0:
        reputation["category"] = "low_risk"
    else:
        reputation["category"] = "unknown"
    
    reputation.update(status='partial', verified=False, source='local_heuristics',
                      limitation='No verified reputation lookup; absence of local signals does not establish safety')
    return reputation

def check_ip_reputation(ip):
    """IP syntax and scope do not establish reputation."""
    result = {'score': 0, 'category': 'unknown', 'status': 'unavailable',
              'sources': [], 'reason': 'No verified reputation provider', 'verified': False}
    if ip:
        try:
            parsed = ipaddress.ip_address(ip)
            result['local_metadata'] = {'is_global': parsed.is_global, 'version': parsed.version}
        except ValueError: result['reason'] = 'Invalid IP address'
    return result

def trace_campaign_origin(headers: dict, hops: list) -> dict:
    """Trace the true origin of phishing campaigns beyond the transmitting server."""
    origin_analysis = {
        "campaign_origin": {},
        "sending_patterns": [],
        "infrastructure_hints": [],
        "attribution_confidence": "low"
    }
    
    # Analyze email headers for campaign patterns
    subject = headers.get("subject", "").lower()
    from_addr = headers.get("from", "").lower()
    
    # 1. Check for known phishing campaign patterns
    campaign_patterns = {
        "business_email_compromise": [
            "wire transfer", "invoice", "payment", "urgent payment", "overdue",
            "account payable", "ceo", "cfo", "director", "newsletter", "announcement"
        ],
        "credential_phishing": [
            "verify account", "login required", "password reset", "security alert",
            "account suspension", "unusual activity"
        ],
        "package_delivery": [
            "package delivery", "shipping notification", "tracking", "fedex", "dhl", "ups"
        ],
        "banking_fraud": [
            "bank account", "credit card", "transaction alert", "security breach"
        ]
    }
    
    detected_campaigns = []
    for campaign_type, patterns in campaign_patterns.items():
        if any(pattern in subject or pattern in from_addr for pattern in patterns):
            detected_campaigns.append(campaign_type)
    
    # Additional BEC detection based on From address patterns
    if "business_email_compromise" not in detected_campaigns:
        # Check for corporate-sounding email addresses
        from_domain = ""
        m = re.search(r"@([^>]+)", from_addr)
        if m:
            from_domain = m.group(1).strip().lower()
            # Corporate domains often have company-like names
            corporate_indicators = ["labs", "tech", "solutions", "systems", "group", "inc", "ltd", "corp"]
            if any(indicator in from_domain for indicator in corporate_indicators):
                detected_campaigns.append("business_email_compromise")
                origin_analysis["infrastructure_hints"].append(f"Corporate domain {from_domain} suggests business email compromise")
    
    if detected_campaigns:
        origin_analysis["campaign_origin"]["detected_types"] = detected_campaigns
        origin_analysis["attribution_confidence"] = "medium"
    
    # 2. Analyze sending infrastructure patterns
    sending_patterns = []
    
    # Identify the first non-Microsoft hop as potential origin
    first_non_ms_hop = None
    for hop in reversed(hops):  # Start from the end (origin)
        from_domain = hop.get("from", "").split("(")[0].strip().lower()
        if not any(ms_domain in from_domain for ms_domain in ["outlook.com", "microsoft", "office365"]):
            first_non_ms_hop = hop
            break
    
    if first_non_ms_hop:
        origin_ip = first_non_ms_hop.get("ip", "")
        origin_domain = first_non_ms_hop.get("from", "").split("(")[0].strip()
        
        if origin_ip:
            sending_patterns.append("non_ms_origin_server")
            origin_analysis["infrastructure_hints"].append(f"Non-Microsoft origin server: {origin_domain} ({origin_ip})")
            origin_analysis["campaign_origin"]["likely_source"] = f"compromised_server_{origin_domain}"
            origin_analysis["attribution_confidence"] = "high"
            
            # 🚀 NUOVO: Analisi ricorsiva dell'infrastruttura compromessa
            recursive_analysis = analyze_compromised_infrastructure(origin_domain, origin_ip) if network_allowed() else {}
            if recursive_analysis:
                origin_analysis["infrastructure_chain"] = recursive_analysis
                origin_analysis["attribution_confidence"] = "very_high"
    
    # Check for cloud provider patterns
    for hop in hops:
        ip = hop.get("ip", "")
        if ip:
            # AWS ranges
            if ipaddress.ip_address(ip) in ipaddress.ip_network('52.0.0.0/8') or \
               ipaddress.ip_address(ip) in ipaddress.ip_network('54.0.0.0/8'):
                sending_patterns.append("aws_ec2_sending")
                origin_analysis["infrastructure_hints"].append("AWS infrastructure commonly used for spam/phishing")
            
            # Azure ranges  
            elif ipaddress.ip_address(ip) in ipaddress.ip_network('13.64.0.0/11'):
                sending_patterns.append("azure_sending")
                origin_analysis["infrastructure_hints"].append("Azure infrastructure - possible compromised account")
            
            # Google Cloud ranges
            elif ipaddress.ip_address(ip) in ipaddress.ip_network('35.184.0.0/13'):
                sending_patterns.append("gcp_sending")
                origin_analysis["infrastructure_hints"].append("Google Cloud - check for compromised service accounts")
    
    # 3. Check for compromised mail server patterns
    from_domain = ""
    m = re.search(r"@([^>]+)", from_addr)
    if m:
        from_domain = m.group(1).strip().lower()
        
        # Known compromised domains or suspicious patterns
        suspicious_domains = [
            "outlook.com", "hotmail.com", "gmail.com", "yahoo.com",  # Free email providers
            "protonmail.com", "tutanota.com"  # Privacy-focused (often abused)
        ]
        
        if any(domain in from_domain for domain in suspicious_domains):
            sending_patterns.append("compromised_free_email")
            origin_analysis["infrastructure_hints"].append(f"From domain {from_domain} suggests compromised email account")
            origin_analysis["attribution_confidence"] = "high"
    
    # 4. Time-based analysis
    received_dates = []
    for hop in hops:
        if hop.get("date"):
            try:
                # Parse various date formats
                date_str = hop["date"]
                if date_str.endswith(" +0000"):
                    date_str = date_str.replace(" +0000", " +00:00")
                elif " +0000" in date_str:
                    date_str = date_str.replace(" +0000", "+00:00")
                
                from email.utils import parsedate_to_datetime
                parsed_date = parsedate_to_datetime(date_str)
                received_dates.append(parsed_date)
            except:
                pass
    
    if len(received_dates) >= 2:
        time_diffs = []
        for i in range(1, len(received_dates)):
            diff = (received_dates[i] - received_dates[i-1]).total_seconds()
            time_diffs.append(diff)
        
        avg_delay = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        
        if avg_delay < 10:  # Very fast relay
            sending_patterns.append("fast_relay_suspicious")
            origin_analysis["infrastructure_hints"].append("Unusually fast email relay - possible direct sending")
        elif avg_delay > 300:  # Slow relay
            sending_patterns.append("slow_relay_bulk")
            origin_analysis["infrastructure_hints"].append("Slow relay pattern - typical of bulk email campaigns")
    
    # 5. Geographic analysis
    countries = []
    for hop in hops:
        ip = hop.get("ip", "")
        if ip:
            try:
                rdap = ip_rdap(ip)
                if rdap and rdap.get("cc"):
                    countries.append(rdap["cc"])
            except:
                pass
    
    unique_countries = list(set(countries))
    if len(unique_countries) > 2:
        sending_patterns.append("multi_country_relay")
        origin_analysis["infrastructure_hints"].append(f"Email relayed through {len(unique_countries)} countries: {', '.join(unique_countries)}")
        origin_analysis["attribution_confidence"] = "high"
    
    origin_analysis["sending_patterns"] = sending_patterns
    
    # 6. Final attribution attempt
    if origin_analysis["attribution_confidence"] == "high":
        if "compromised_free_email" in sending_patterns:
            origin_analysis["campaign_origin"]["likely_source"] = "compromised_email_account"
        elif "multi_country_relay" in sending_patterns:
            origin_analysis["campaign_origin"]["likely_source"] = "professional_phishing_service"
        elif any("aws" in p or "azure" in p or "gcp" in p for p in sending_patterns):
            origin_analysis["campaign_origin"]["likely_source"] = "cloud_compromised_infrastructure"
    
    # Header and hosting patterns are hypotheses, not calibrated attribution.
    campaign = origin_analysis['campaign_origin']
    if 'likely_source' in campaign:
        campaign['heuristic_source_hypothesis'] = campaign.pop('likely_source')
    origin_analysis['attribution_confidence'] = 'unavailable'
    origin_analysis['status'] = 'hypotheses_only'
    origin_analysis['limitation'] = 'Header patterns do not establish an actor or compromised infrastructure'
    return origin_analysis

def analyze_phishing_content(body_text, subject, from_addr):
    """Analyze email content for phishing indicators."""
    analysis = {
        "phishing_score": 0,
        "indicators": [],
        "urgency_words": [],
        "threat_words": [],
        "suspicious_patterns": []
    }
    
    text_to_analyze = (body_text + " " + subject + " " + from_addr).lower()
    
    # Urgency indicators
    urgency_indicators = [
        'urgent', 'immediate', 'action required', 'time sensitive', 'deadline', 
        'expires', 'limited time', 'act now', 'do not delay', 'critical',
        'warning', 'alert', 'attention', 'important', 'priority'
    ]
    
    for indicator in urgency_indicators:
        if indicator in text_to_analyze:
            analysis["phishing_score"] += 1
            analysis["urgency_words"].append(indicator)
    
    # Threat indicators  
    threat_indicators = [
        'account suspended', 'account blocked', 'account locked', 'security breach',
        'unauthorized access', 'suspicious activity', 'verify your account',
        'confirm your identity', 'password expired', 'login failed',
        'payment declined', 'billing issue', 'refund', 'chargeback',
        'account is suspended', 'account has been suspended', 'suspended account'
    ]
    
    for indicator in threat_indicators:
        if indicator in text_to_analyze:
            analysis["phishing_score"] += 2
            analysis["threat_words"].append(indicator)
    
    # Suspicious patterns
    patterns = [
        r'\b\d{4,}\b',  # Reference numbers
        r'\bID[:#]\s*\w+',  # ID references
        r'\bref[:#]\s*\w+',  # Reference numbers
        r'\bcustomer\s+support\b',
        r'\btechnical\s+support\b',
        r'\bsecurity\s+team\b'
    ]
    
    import re
    for pattern in patterns:
        if re.search(pattern, text_to_analyze, re.IGNORECASE):
            analysis["phishing_score"] += 1
            analysis["suspicious_patterns"].append(pattern)
    
    # Language analysis - mixed languages can be suspicious
    if any(word in text_to_analyze for word in ['konto', 'vil', 'blive', 'bekræft']) and \
       any(word in text_to_analyze for word in ['account', 'verify', 'confirm', 'login']):
        analysis["phishing_score"] += 2
        analysis["indicators"].append("mixed_languages")
    
    return analysis

from .graphs import attribution_graph, domain_graph, detonation_box, canary_box
from .evidence import merkle_root, write_index
from .stix import make_stix
from .abuse import generate_abuse_package, generate_arf_package, generate_xarf_package
from .rekor import anchor_case
from ..intelligence.criminal_hunter import CriminalHunter
from ..intelligence.infrastructure_mapper import InfrastructureMapper
from ..intelligence.enrich_last_hunt import safe_getcert, grab_banner, reverse_dns, whois_lookup, asn_lookup
from ..intelligence.threat_intel import ThreatIntelligence

@enforce_trace_policy
def trace_sources(src, lang, stix, abuse, anchor, no_egress, profile="default", deob_weight: float = 0.30, dkim_key_evidence=None):
    deob_weight = validate_deobfuscation_weight(deob_weight)
    if dkim_key_evidence is not None: parse_key_evidence(dkim_key_evidence)
    inputs = select_inputs(src)
    if os.path.isfile(src):
        return [trace_one(str(inputs[0]), lang, stix, abuse, anchor, no_egress, profile, deob_weight, dkim_key_evidence)]
    cases, failures = [], []
    for path in inputs:
        mark_stage('batch_input')
        try:
            cases.append(trace_one(str(path), lang, stix, abuse, anchor, no_egress, profile, deob_weight, dkim_key_evidence))
        except Exception as exc:
            failures.append({'input':path.name, 'error':f'{type(exc).__name__}: {exc}'})
            print(f'[batch] failed {path.name}: {type(exc).__name__}: {exc}')
    if failures:
        raise BatchAnalysisError(cases, failures, [path.name for path in inputs])
    return cases

@enforce_trace_policy
def trace_one(eml_path, lang, stix, abuse, anchor, no_egress, profile="default", deob_weight: float = 0.30, dkim_key_evidence=None):
    deob_weight = validate_deobfuscation_weight(deob_weight)
    key_data = parse_key_evidence(dkim_key_evidence) if dkim_key_evidence is not None else None
    import re
    mark_stage('mime_parsing')
    started = time.perf_counter()
    violations_before = len(violations())
    headers, msg, b = load_mail(eml_path)
    header_inventory = inventory_headers(msg, b)
    mime_header_inventory = inventory_mime_headers(msg, b)
    mime_result = analyze_mime(msg)
    case_id = sanitize_case_id(utc_now_iso().replace(":","").replace("Z","Z-") + uuid.uuid4().hex)
    case_dir = os.path.join(os.getcwd(), "cases", "case-" + case_id)
    os.makedirs(case_dir,exist_ok=False)
    mark_stage('ingest', os.path.basename(case_dir))
    
    # Ingest
    eml_hash = blake3_hex(b)
    with open(os.path.join(case_dir,"input.eml"), "wb") as original:
        original.write(b)
    write_json(os.path.join(case_dir, 'header_inventory.json'), header_inventory)
    write_json(os.path.join(case_dir, 'mime_header_inventory.json'), mime_header_inventory)
    manifest = {"case_id": case_id, "created_utc": utc_now_iso(), "inputs":[{"path":"input.eml","blake3": eml_hash, "size": len(b)}], "policy":{"no_egress": bool(no_egress)}, "deobfuscation_weight": float(deob_weight)}
    manifest['source_name'] = os.path.basename(eml_path)
    if key_data is not None:
        key_raw, key_bundle, key_records = key_data
        import hashlib
        with open(os.path.join(case_dir, 'dkim_keys.json'), 'wb') as stream:
            stream.write(key_raw)
        manifest['dkim_key_evidence'] = {'path':'dkim_keys.json',
            'sha256':hashlib.sha256(key_raw).hexdigest(), 'provenance_status':'unverified',
            'source_claim':key_bundle['source']}
    if os.environ.get('PAW_ANALYSIS_ID'):
        manifest['analysis_job'] = os.environ['PAW_ANALYSIS_ID']
    write_json(os.path.join(case_dir, 'manifest.json'), manifest)
    # PGP sign manifest if keys available
    if os.environ.get("PAW_PGP_PRIV"):
        try:
            from .signature import sign_file_pgp
            manifest_path = os.path.join(case_dir, "manifest.json")
            sig_path = os.path.join(case_dir, "evidence", "manifest.json.asc")
            sign_file_pgp(manifest_path, os.environ["PAW_PGP_PRIV"], os.environ.get("PAW_PGP_PASS"), sig_path)
            print(f"[pgp] manifest signed: {sig_path}")
        except Exception as e:
            print(f"[pgp] signing failed: {e}")
    write_json(os.path.join(case_dir, 'mime_analysis.json'), mime_result['metadata'])
    body_inventory = preserve_body_parts(mime_result, b, os.path.join(case_dir, 'mime_body'))
    write_json(os.path.join(case_dir, 'mime_body_evidence.json'), body_inventory)
    body_text = mime_result['body_text']
    from .mime_analysis import extract_urls
    from .url_evidence import extract_mime_url_candidates, build_url_evidence
    observed_urls = list(dict.fromkeys(mime_result['urls'] +
        extract_urls(headers.get('subject', '')) + extract_urls(headers.get('from', ''))))
    headers['mime_status'] = mime_result['metadata']['status']

    # Deobfuscate content to reveal hidden URLs and malicious content
    mark_stage('deobfuscation')
    deobfuscation_engine = DeobfuscationEngine()
    
    # Combine all text content for analysis
    full_text = body_text
    if headers.get("subject"):
        full_text += " " + headers["subject"]
    
    potential_urls = extract_mime_url_candidates(mime_result, headers.get('subject', ''))
    
    deobfuscation_artifacts = {
        "text": full_text,
        "urls": list(dict.fromkeys(observed_urls + potential_urls)),
        "html": mime_result["html"],
        "javascript": mime_result["javascript"],
        "attachments": []
    }
    
    deobfuscation_results = deobfuscation_engine.analyze_artifacts(deobfuscation_artifacts)
    headers["deobfuscation_analysis"] = deobfuscation_results
    # Persist deobfuscation results in the case directory for downstream analysis
    try:
        write_json(os.path.join(case_dir, "deobfuscation_results.json"), deobfuscation_results)
    except Exception as e:
        print(f"[deobfuscate] failed to write deobfuscation_results.json: {e}")
    
    # Keep network destinations separate from decoded payloads and comparison
    # metadata. Malformed observations remain evidence, without entering URLs.
    deobfuscated = deobfuscation_results.get("deobfuscated_artifacts", {})
    urls, url_evidence = build_url_evidence(observed_urls, deobfuscated.get('urls', []))
    headers['urls'] = urls
    headers['url_evidence'] = url_evidence
    write_json(os.path.join(case_dir, 'url_evidence.json'), url_evidence)
    
    # Analyze content for phishing indicators
    subject = headers.get("subject", "")
    from_addr = headers.get("from", "")
    phishing_analysis = analyze_phishing_content(body_text, subject, from_addr)
    headers["phishing_analysis"] = phishing_analysis
    
    # Auxiliary observations, not a trained classifier or authorization to act.
    # Keep the legacy artifact key; schema_version=2 describes the new contract.
    from .ml_scorer import analyze_content_indicators
    ml_score = analyze_content_indicators({
        'subject': subject,
        'body': body_text,
        'from': from_addr
    })
    headers["ml_score"] = ml_score
    
    # Observed indicators are never augmented with analyst-created canary URLs.

    # Analyze domain reputation for found URLs
    if urls:
        domain_analysis = []
        for url in urls:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    reputation = check_domain_reputation(domain)
                    domain_analysis.append({
                        "url": url,
                        "domain": domain,
                        "reputation": reputation
                    })
            except Exception as e:
                domain_analysis.append({
                    "url": url,
                    "domain": "error",
                    "reputation": {"score": 0, "category": "error", "sources": [str(e)]}
                })
        headers["domain_analysis"] = domain_analysis
    
    write_json(os.path.join(case_dir,"headers.json"), {key: value for key, value in headers.items() if key != "_msg_obj"})
    stage_status = {'detonation': {'status': 'skipped', 'reason': 'no-egress' if no_egress else 'No URLs'},
                    'network_enrichment': {'status': 'skipped' if no_egress else 'not_evaluated', 'reason': 'no-egress' if no_egress else 'Individual lookup outcomes apply'},
                    'attachment_metadata': {'status': 'not_evaluated'}}
    stage_status['header_inventory'] = inventory_coverage(header_inventory)
    stage_status['mime_header_inventory'] = mime_header_coverage(mime_header_inventory)
    stage_status['mime_body_evidence'] = body_evidence_coverage(body_inventory)
    url_results = deobfuscated.get('urls', [])
    stage_status['url_interpretation'] = {
        'status':'partial' if any(r.get('status') != 'completed' or r.get('analysis_status') == 'partial'
                                  for r in url_results) else 'completed',
        'observed_count':len(observed_urls), 'network_target_count':len(urls),
        'invalid_or_unresolved_count':sum(r.get('status') != 'completed' for r in url_results),
        'limited_analysis_count':sum(r.get('analysis_status') == 'partial' for r in url_results),
        'embedded_candidate_count':sum(len(r.get('embedded_url_candidates', [])) for r in url_results),
        'limitation':'Embedded destinations and visual comparisons are unverified; syntax validity is not authenticity'}
    # Automatic detonation if URLs found
    mark_stage('detonation')
    if urls and not no_egress:
        print(f"[detonate] found {len(urls)} URLs, starting automatic detonation...")
        try:
            from ..detonate.runner import run_detonation
            case_id_short = os.path.basename(case_dir)
            det_result = run_detonation(url=None, case_id=case_id_short, timeout=35, capture_pcap=False, headless=True, observe_only=True)
            stage_status["detonation"] = {"status": (read_json(os.path.join(case_dir, "detonation", "summary.json")) or {}).get("status", "not_evaluated")}
        except Exception as e:
            stage_status["detonation"] = {"status": "failed", "reason": str(e)}
            print(f"[detonate] automatic detonation failed: {e}")
        
        # Canary deployment is an explicit CLI operation, never an analysis side effect.
    # Scan attachments if present
    mark_stage('attachment_metadata')
    atts = []
    if "_msg_obj" in headers or msg:
        try:
            from .attach import scan_attachments
            atts = scan_attachments(msg, mime_result=mime_result, evidence_dir=os.path.join(case_dir, "attachments"))
            write_json(os.path.join(case_dir,"attachments.json"), atts)
            stage_status["attachment_metadata"] = {"status": "partial" if any(item["status"] == "partial" for item in atts) else "completed", "count": len(atts), "malware_analysis": "not_evaluated"}
        except Exception as e:
            stage_status["attachment_metadata"] = {"status": "failed", "reason": str(e)}
            print(f"[attach] scanning failed: {e}")
    # Normalize Received
    mark_stage('headers_authentication')
    norm = normalize_received(headers.get("received") or [])
    hops = norm.get("ordered_hops") or []
    write_json(os.path.join(case_dir,"received_path.json"), norm)
    # Choose origin candidate: prefer first hop with public IP NOT 'recipient_mx_internal'
    def _is_public_ip(s):
        from .ip_observations import classify_ip
        return classify_ip(s)['category'] == 'public'

    origin = {}
    # Prefer external_ingress hops (email entering MX protection)
    for h in hops:
        if h.get("ip") and _is_public_ip(h["ip"]) and h.get("role") == "external_ingress":
            origin = h
            break
    # Fallback: internet_origin_candidate hops
    if not origin:
        for h in hops:
            if h.get("ip") and _is_public_ip(h["ip"]) and h.get("role") == "internet_origin_candidate":
                origin = h
                break
    # Fallback: any public IP not recipient_mx_internal
    if not origin:
        for h in hops:
            if h.get("ip") and _is_public_ip(h["ip"]) and h.get("role") != "recipient_mx_internal":
                origin = h
                break
    # Fallback: any public IP
    if not origin:
        for h in hops:
            if h.get("ip") and _is_public_ip(h["ip"]):
                origin = h
                break
    # Fallback: any IP
    if not origin and hops:
        for h in hops:
            if h.get("ip"):
                origin = h
                break
    # Last resort: first hop
    if not origin and hops:
        origin = hops[0]
    # Auth alignment (from Authentication-Results)
    auth = infer_alignment(headers, headers.get("from",""), headers.get("return_path",""))
    auth["dkim"]["verification"] = verify_dkim_offline(b, key_records if key_data is not None else None)
    if key_data is not None:
        auth['dkim']['key_evidence'] = manifest['dkim_key_evidence']
    write_json(os.path.join(case_dir,"auth.json"), auth)
    # Analyze received path for campaign origin
    campaign_origin = trace_campaign_origin(headers, hops)
    write_json(os.path.join(case_dir,"campaign_origin.json"), campaign_origin)
    
    # Profile IP RDAP
    mark_stage('ip_enrichment')
    ip = origin.get("ip") or ""
    ip_res = ip_rdap(ip) if ip else {}
    origin_out = {"ip": ip, "asn": ip_res.get("asn"), "org": ip_res.get("asn_org"), "cc": ip_res.get("cc"), "abuse": ip_res.get("abuse", []),
                  "time_utc": origin.get("date"), "helo": origin.get("helo"), "ptr": origin.get("ptr"), "skew_s": origin.get("skew_s"),
                  'timing_observation':origin.get('timing_observation'),
                  "reputation": check_ip_reputation(ip),
                  "status": "candidate" if ip else "unavailable", "source": "Received header",
                  "verified": False, "limitation": "Header chain and receiver boundary are not independently authenticated",
                  'received_header_index':origin.get('header_index'),
                  'ip_observation':origin.get('ip_observation'),
                  'role_observation':origin.get('role_observation'),
                  "enrichment_status": ip_res.get("status", "error" if ip_res.get("error") else "available" if ip else "unavailable")}
    write_json(os.path.join(case_dir,"transmitting_server.json"), origin_out)
    # Create origin.json alias for compatibility with abuse package
    write_json(os.path.join(case_dir,"origin.json"), origin_out)
    # Merge detonation endpoints → infra hints
    det_sum = os.path.join(case_dir, "detonation", "summary.json")
    if os.path.exists(det_sum):
        det = read_json(det_sum) or {}
        endpoints = det.get("endpoints", [])
        write_json(os.path.join(case_dir,"detonation_endpoints.json"), endpoints)
        
        # Automatic OSINT on detonation IPs (C2 infrastructure mapping)
        if endpoints:
            print("[osint] analyzing detonation infrastructure...")
            c2_analysis = []
            for ep in endpoints:
                ips = ep.get("ips", [])
                if ips:  # Check if ips list is not empty
                    ep_ip = ips[0]  # Take first IP
                    if ep_ip:
                        # RDAP lookup for ASN/Org info
                        rdap = ip_rdap(ep_ip) if ep_ip else {}
                        # Reverse DNS for additional domains
                        try:
                            import socket
                            ptr_records = socket.gethostbyaddr(ep_ip)[0] if ep_ip else ""
                        except:
                            ptr_records = ""
                        
                        c2_analysis.append({
                            "host": ep.get("host"),
                            "ip": ep_ip,
                            "asn": rdap.get("asn"),
                            "org": rdap.get("asn_org"),
                            "country": rdap.get("cc"),
                            "asn_country": rdap.get("asn_cc"),
                            "ptr": ptr_records,
                            "abuse_contacts": rdap.get("abuse", []),
                            "reputation": check_ip_reputation(ep_ip)
                        })
            write_json(os.path.join(case_dir,"c2_infrastructure.json"), c2_analysis)
            print(f"[osint] analyzed {len(c2_analysis)} infrastructure endpoints")

            # 🚀 NUOVO: Analisi del phishing kit estratto per pattern C2
            kit_dir = os.path.join(case_dir, "detonation", "runs")
            if os.path.exists(kit_dir):
                print("[kit] analyzing extracted phishing kit for C2 patterns...")
                kit_content = {}

                # Carica i file estratti
                for kit_root, _, kit_files in os.walk(kit_dir):
                    for filename in kit_files:
                        filepath = os.path.join(kit_root, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            if filename.endswith('.html'):
                                kit_content.setdefault('html', []).append(content)
                            elif filename.endswith('.js'):
                                kit_content.setdefault('javascript', []).append(content)
                            elif filename.endswith('.css'):
                                kit_content.setdefault('css', []).append(content)
                        except Exception as e:
                            print(f"[kit] error reading {filename}: {e}")

                # Analizza il contenuto del kit
                if kit_content:
                    kit_analysis = analyze_phishing_kit_content(kit_content)
                    write_json(os.path.join(case_dir, "phishing_kit_analysis.json"), kit_analysis)
                    print(f"[kit] analyzed kit with risk level: {kit_analysis.get('risk_level', 'unknown')}")

                    # Integra nell'analisi della campagna
                    campaign_origin = read_json(os.path.join(case_dir, "campaign_origin.json")) or {}
                    if kit_analysis.get('c2_servers') or kit_analysis.get('exfiltration_endpoints'):
                        campaign_origin.setdefault('infrastructure_chain', {})
                        campaign_origin['infrastructure_chain']['kit_c2_analysis'] = kit_analysis
                        campaign_origin['attribution_confidence'] = 'unavailable'
                        write_json(os.path.join(case_dir, "campaign_origin.json"), campaign_origin)
                        print("[kit] integrated kit analysis into campaign origin")

            # 🚀 NUOVO: Integrazione Criminal Hunter per analisi infrastrutturale avanzata
            print("[criminal_hunter] starting advanced infrastructure analysis...")
            try:
                hunter = CriminalHunter()
                
                # Analizza tutti gli endpoint C2 trovati
                criminal_intel = []
                for ep in endpoints:
                    host = ep.get("host", "")
                    if host:
                        try:
                            hunt_result = hunter.hunt_from_domain(host)
                            if hunt_result:
                                criminal_intel.append({
                                    "target_domain": host,
                                    "criminal_analysis": hunt_result
                                })
                                print(f"[criminal_hunter] analyzed infrastructure for {host}")
                        except Exception as e:
                            print(f"[criminal_hunter] failed to analyze {host}: {e}")
                
                if criminal_intel:
                    write_json(os.path.join(case_dir, "criminal_intelligence.json"), criminal_intel)
                    print(f"[criminal_hunter] completed analysis for {len(criminal_intel)} domains")
                    
                    # Integra nell'attribution matrix se disponibile
                    matrix_file = os.path.join(case_dir, "attribution_matrix.json")
                    if os.path.exists(matrix_file):
                        matrix_data = read_json(matrix_file) or {}
                        matrix_data["criminal_intelligence"] = criminal_intel
                        write_json(matrix_file, matrix_data)
                        print("[criminal_hunter] integrated into attribution matrix")
                        
            except Exception as e:
                print(f"[criminal_hunter] failed: {e}")

            # 🚀 NUOVO: Integrazione Infrastructure Mapper per mappatura avanzata
            print("[infrastructure_mapper] starting advanced network mapping...")
            try:
                mapper = InfrastructureMapper()
                
                # Raccogli tutti gli IP dall'analisi C2
                all_ips = []
                for ep in endpoints:
                    ips = ep.get("ips", [])
                    if isinstance(ips, list):
                        all_ips.extend(ips)
                
                # Rimuovi duplicati
                all_ips = list(set(all_ips))
                
                if all_ips and len(all_ips) > 0:
                    # Prendi il dominio principale dalla campagna
                    target_domain = ""
                    for ep in endpoints:
                        host = ep.get("host", "")
                        if host and "." in host:
                            target_domain = host
                            break
                    
                    # Fallback: usa il primo URL detonato
                    if not target_domain and urls and isinstance(urls, list) and len(urls) > 0:
                        from urllib.parse import urlparse
                        try:
                            parsed = urlparse(urls[0])
                            target_domain = parsed.netloc or ""
                        except:
                            pass
                    
                    if target_domain:
                        try:
                            infra_map = mapper.comprehensive_map(target_domain, all_ips)
                            if infra_map:
                                write_json(os.path.join(case_dir, "infrastructure_mapping.json"), infra_map)
                                print(f"[infrastructure_mapper] completed mapping for {len(all_ips)} IPs")
                                
                                # Integra nell'attribution matrix
                                matrix_file = os.path.join(case_dir, "attribution_matrix.json")
                                if os.path.exists(matrix_file):
                                    matrix_data = read_json(matrix_file) or {}
                                    matrix_data["infrastructure_mapping"] = infra_map
                                    write_json(matrix_file, matrix_data)
                                    print("[infrastructure_mapper] integrated into attribution matrix")
                        except Exception as map_err:
                            print(f"[infrastructure_mapper] comprehensive_map failed: {map_err}")
                    else:
                        print("[infrastructure_mapper] No target domain found, skipping mapping")
                else:
                    print("[infrastructure_mapper] No IPs found for mapping, skipping")
                            
            except Exception as e:
                print(f"[infrastructure_mapper] failed: {e}")

            # 🚀 NUOVO: Integrazione Enrich Last Hunt per arricchimento SSL e banner
            print("[enrich_last_hunt] starting SSL certificate and banner enrichment...")
            try:
                hunt_enrichments = []
                
                # Arricchisci tutti gli IP dell'infrastruttura C2
                for ep in endpoints:
                    ips = ep.get("ips", [])
                    host = ep.get("host", "")
                    
                    for enrich_ip in ips:
                        try:
                            # Ottieni certificato SSL
                            cert_data = safe_getcert(host, port=443)
                            
                            # Ottieni banner dei servizi comuni
                            banners = {}
                            common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
                            for port in common_ports:
                                banner = grab_banner(enrich_ip, port)
                                if banner and not banner.startswith('{"'):
                                    banners[str(port)] = banner
                            
                            # Reverse DNS
                            rdns = reverse_dns(enrich_ip)
                            
                            # WHOIS e ASN lookup
                            whois_data = whois_lookup(host) if host else {}
                            asn_data = asn_lookup(enrich_ip)
                            
                            enrichment = {
                                "ip": enrich_ip,
                                "host": host,
                                "ssl_certificate": cert_data,
                                "service_banners": banners,
                                "reverse_dns": rdns,
                                "whois": whois_data,
                                "asn_info": asn_data
                            }
                            
                            hunt_enrichments.append(enrichment)
                            print(f"[enrich_last_hunt] enriched {enrich_ip} ({host})")
                            
                        except Exception as e:
                            hunt_enrichments.append({
                                "ip": enrich_ip,
                                "host": host,
                                "error": str(e)
                            })
                
                if hunt_enrichments:
                    # Clean hunt_enrichments to remove non-serializable data
                    def clean_for_json(obj):
                        if isinstance(obj, dict):
                            return {k: clean_for_json(v) for k, v in obj.items() if not isinstance(v, bytes)}
                        elif isinstance(obj, list):
                            return [clean_for_json(item) for item in obj]
                        elif isinstance(obj, (str, int, float, bool)) or obj is None:
                            return obj
                        else:
                            return str(obj)  # Convert other types to string
                    
                    clean_enrichments = clean_for_json(hunt_enrichments)
                    write_json(os.path.join(case_dir, "hunt_enrichments.json"), clean_enrichments)
                    print(f"[enrich_last_hunt] completed enrichment for {len(clean_enrichments)} endpoints")
                    
                    # Integra nell'attribution matrix
                    matrix_file = os.path.join(case_dir, "attribution_matrix.json")
                    if os.path.exists(matrix_file):
                        matrix_data = read_json(matrix_file) or {}
                        matrix_data["hunt_enrichments"] = hunt_enrichments
                        write_json(matrix_file, matrix_data)
                        print("[enrich_last_hunt] integrated into attribution matrix")
                        
            except Exception as e:
                print(f"[enrich_last_hunt] failed: {e}")

    # Merge canary hits → attacker_visit
    hits = os.path.join(case_dir, "canary", "hits.jsonl")
    if os.path.exists(hits):
        ips = set()
        canary_visitors = []
        with open(hits,"r",encoding="utf-8") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    visitor_ip = j.get("ip")
                    if visitor_ip:
                        ips.add(visitor_ip)
                        canary_visitors.append({
                            "ip": visitor_ip,
                            "timestamp": j.get("ts"),
                            "user_agent": j.get("ua"),
                            "url": j.get("url"),
                            "reputation": check_ip_reputation(visitor_ip)
                        })
                except Exception: pass
        write_json(os.path.join(case_dir,"canary_ips.json"), sorted([cip for cip in ips if cip]))
        write_json(os.path.join(case_dir,"canary_visitors.json"), canary_visitors)
    # From domain info
    mark_stage('domain_enrichment')
    from_addr = headers.get("from","")
    import re
    m = re.search(r"@([^>]+)", from_addr or "")
    from_domain = auth.get("from_domain") or ""
    dominfo = {"from_domain": {"domain": from_domain}}
    if from_domain:
        dr = domain_rdap(from_domain)
        dominfo["from_domain"] = dr
    age_observation = observe_domain_age(dominfo['from_domain'].get('created'))
    age_observation['source'] = 'domains.json.from_domain.created'
    dominfo['from_domain']['domain_age'] = age_observation
    dominfo['from_domain']['nrd_days'] = age_observation['age_days']
    write_json(os.path.join(case_dir,"domains.json"), dominfo)
    
    # 🚀 NUOVO: Correlazione automatica Threat Intelligence
    print("[threat_intel] starting automatic threat intelligence correlation...")
    try:
        ti = ThreatIntelligence()

        # Raccogli tutti i domini e IP dall'analisi precedente
        all_domains = []
        all_ips = []

        # Da campaign_origin
        campaign_data = read_json(os.path.join(case_dir, "campaign_origin.json")) or {}
        if campaign_data.get("domain"):
            all_domains.append(campaign_data["domain"])

        # Da domains.json
        domains_data = read_json(os.path.join(case_dir, "domains.json")) or {}
        from_domain = domains_data.get("from_domain", {}).get("domain")
        if from_domain:
            all_domains.append(from_domain)

        # Da detonation_endpoints
        det_endpoints = read_json(os.path.join(case_dir, "detonation_endpoints.json")) or []
        for ep in det_endpoints:
            host = ep.get("host")
            if host:
                all_domains.append(host)
            ips = ep.get("ips", [])
            all_ips.extend(ips)

        # Da c2_infrastructure
        c2_infra = read_json(os.path.join(case_dir, "c2_infrastructure.json")) or []
        for infra in c2_infra:
            c2_ip = infra.get("ip")
            if c2_ip:
                all_ips.append(c2_ip)

        # Rimuovi duplicati
        all_domains = list(set(all_domains))
        all_ips = list(set(all_ips))

        # Correlazione threat intelligence
        threat_correlations = {}
        if all_domains or all_ips:
            for domain in all_domains:
                if domain:
                    try:
                        domain_intel = ti.enrich_indicators(domain, [])
                        threat_correlations[f"domain_{domain}"] = domain_intel
                        print(f"[threat_intel] recorded provider availability for domain: {domain}")
                    except Exception as e:
                        print(f"[threat_intel] failed to correlate domain {domain}: {e}")

            # Correlazione per IP (raggruppa per evitare troppe chiamate API)
            if all_ips:
                try:
                    ip_intel = ti.enrich_indicators("", all_ips)
                    threat_correlations["ip_intelligence"] = ip_intel
                    print(f"[threat_intel] recorded provider availability for {len(all_ips)} IPs")
                except Exception as e:
                    print(f"[threat_intel] failed to correlate IPs: {e}")

        if threat_correlations:
            write_json(os.path.join(case_dir, "threat_intelligence.json"), threat_correlations)
            print(f"[threat_intel] recorded availability for {len(threat_correlations)} indicator groups")

            # Integra nell'attribution matrix
            matrix_file = os.path.join(case_dir, "attribution_matrix.json")
            if os.path.exists(matrix_file):
                matrix_data = read_json(matrix_file) or {}
                matrix_data["threat_intelligence"] = threat_correlations
                write_json(matrix_file, matrix_data)
                print("[threat_intel] integrated into attribution matrix")

    except Exception as e:
        print(f"[threat_intel] failed: {e}")
    
    # 🚀 NUOVO: Crea Attribution Matrix Unificata
    print("[attribution_matrix] creating unified attribution matrix...")
    try:
        attribution_matrix = {
            "case_id": os.path.basename(case_dir),
            "timestamp": utc_now_iso(),
            "intelligence_modules": {
                "criminal_hunter": read_json(os.path.join(case_dir, "criminal_intelligence.json")) or {},
                "infrastructure_mapper": read_json(os.path.join(case_dir, "infrastructure_mapping.json")) or {},
                "enrich_last_hunt": read_json(os.path.join(case_dir, "hunt_enrichments.json")) or {},
                "threat_intelligence": read_json(os.path.join(case_dir, "threat_intelligence.json")) or {},
                "c2_infrastructure": read_json(os.path.join(case_dir, "c2_infrastructure.json")) or {},
                "phishing_kit_analysis": read_json(os.path.join(case_dir, "phishing_kit_analysis.json")) or {}
            },
            "campaign_analysis": {
                "campaign_origin": read_json(os.path.join(case_dir, "campaign_origin.json")) or {},
                "detonation_endpoints": read_json(os.path.join(case_dir, "detonation_endpoints.json")) or [],
                "domains": read_json(os.path.join(case_dir, "domains.json")) or {},
                "transmitting_server": read_json(os.path.join(case_dir, "transmitting_server.json")) or {}
            },
            "operator_hypothesis": {
                "confidence": 0.0,
                "hypothesis": "Analysis in progress",
                "evidence_count": 0
            }
        }
        
        write_json(os.path.join(case_dir, "attribution_matrix.json"), attribution_matrix)
        print("[attribution_matrix] unified matrix created successfully")
        
    except Exception as e:
        print(f"[attribution_matrix] failed to create: {e}")
    
    # Header forgery analysis
    mark_stage('scoring')
    from .header_forgery import analyze_received_anomalies, received_score_components
    anomalies = analyze_received_anomalies(hops)
    write_json(os.path.join(case_dir,"received_anomalies.json"), anomalies)
    # Score
    suspicious_asn = False  # could be enhanced with local list
    ns_mx_recurrent = False # could be enhanced with local list
    # Timestamp differences and By-host syntax are unverified descriptions,
    # not evidence of malicious routing or a verified receiver boundary.
    hop_diag = {"skew_s": None, "helo_ptr_match": origin.get("helo_ptr_match"), "fqdn_ok": None}
    # Load detonation/canary data for scoring bonuses
    detonation_endpoints = []
    canary_ips = []
    det_summary = {}
    
    det_endpoints_path = os.path.join(case_dir,"detonation_endpoints.json")
    if os.path.exists(det_endpoints_path):
        detonation_endpoints = read_json(det_endpoints_path) or []
    
    canary_ips_path = os.path.join(case_dir,"canary_ips.json")
    if os.path.exists(canary_ips_path):
        canary_ips = read_json(canary_ips_path) or []
    
    det_summary_path = os.path.join(case_dir,"detonation","summary.json")
    if os.path.exists(det_summary_path):
        det_summary = read_json(det_summary_path) or {}
    score = score_case(hop_diag, auth, {"domain":from_domain, "nrd_days": dominfo["from_domain"].get("nrd_days")}, brand_seeds=None, suspicious_asn=suspicious_asn, ns_mx_recurrent=ns_mx_recurrent, profile=profile, headers=headers, detonation_endpoints=detonation_endpoints, canary_ips=canary_ips, det_summary=det_summary, origin_domain=from_domain, deobfuscation_weight=deob_weight)
    # Preserve each unverified structural signal and the unrounded base sum.
    score = finalize_score(score, profile, additional_components=received_score_components(anomalies))
    stage_status['header_parsing'] = {'status': 'partial' if headers.get('header_defects') or headers.get('from_header_count') != 1 or (headers.get('from_identity') or {}).get('status') != 'parsed' or (headers.get('reply_to_domain') or {}).get('status') not in {'parsed','unavailable'} else 'completed',
                                     'defects': headers.get('header_defects') or [],
                                     'field_defects': headers.get('header_field_defects') or [],
                                     'from_identity': headers.get('from_identity') or {},
                                     'reply_to_domain': headers.get('reply_to_domain') or {},
                                     'reply_to_header_count': headers.get('reply_to_header_count'),
                                     'from_header_count': headers.get('from_header_count')}
    stage_status['reply_to_comparison'] = score['sender_domain_observations']['reply_to_comparison']
    stage_status['unicode_domain'] = score['sender_domain_observations']['unicode_domain']
    stage_status['display_brand_comparison'] = score['sender_domain_observations']['display_brand_comparison']
    stage_status['domain_brand_comparison'] = score['sender_domain_observations']['domain_brand_comparison']
    stage_status['tld_comparison'] = score['sender_domain_observations']['tld_comparison']
    stage_status['domain_age'] = age_observation
    if age_observation['status'] != 'observed_unverified':
        score['coverage']['not_evaluated'].append('domain_age')
    stage_status['mime_parsing'] = {'status': mime_result['metadata']['status'], 'issues': mime_result['metadata']['issues']}
    stage_status['received_path'] = {'status': 'partial' if norm['status']=='partial' else 'parsed_unverified' if hops else 'unavailable',
        'verified':False,'schema_version':norm['received_schema_version'],
        'parsing_issues':[{'header_index':h['header_index'],'issues':h['parsing']['issues']} for h in hops if h['parsing']['issues']],
        'receiver_boundary':anomalies['receiver_boundary'],
        'descriptive_components':['received_private_ip_before_boundary','received_invalid_fqdn']}
    timing = anomalies['timing_observations']
    stage_status['received_timing'] = {'status':timing['status'],'verified':False,
        'schema_version':timing['timing_schema_version'],'comparison_status':timing['comparison_status'],
        'adjacent_pair_count':len(timing['adjacent_pairs']),
        'available_pair_count':sum(pair['status']=='completed' for pair in timing['adjacent_pairs']),
        'interpretation_status':timing['interpretation_status']}
    correlations = correlate_campaigns(os.path.dirname(case_dir))
    stage_status['campaign_correlation'] = {'status':correlations['status'], 'reason':correlations['reason']}
    stage_status['stix_export'] = {'status':'unavailable' if stix else 'skipped',
                                 'reason':'STIX schema conformance not validated' if stix else 'Not requested'}
    stage_status['abuse_formats'] = {'status':'partial' if abuse else 'skipped',
                                   'reason':'Local review drafts; ARF/X-ARF conformance not validated' if abuse else 'Not requested'}
    score['coverage']['not_evaluated'].append('campaign_correlation')
    if stix: score['coverage']['not_evaluated'].append('stix_export')
    if abuse: score['coverage']['not_evaluated'].append('arf_xarf_conformance')
    score['assessment_status'] = 'partial'
    write_json(os.path.join(case_dir, 'campaign_correlations.json'), correlations)
    score['coverage']['stages'] = stage_status
    write_json(os.path.join(case_dir, 'analysis_coverage.json'), score['coverage'])
    write_json(os.path.join(case_dir,"report/score.json"), score)
    # Index case in database
    try:
        from .index import upsert_case
        upsert_case(case_dir, origin_out, headers, dominfo["from_domain"], score)
        
        # Repeated submissions are not independent evidence of maliciousness.
    except Exception as e:
        print(f"[index] failed to index case: {e}")
    # Graphs
    graphs_dir = os.path.join(case_dir,"graphs")
    ensure_dir(graphs_dir)
    # Find origin hop index (1-based)
    origin_idx = 1
    for i, h in enumerate(hops, start=1):
        if h.get("ip") == origin.get("ip"):
            origin_idx = i
            break
    mmd1 = attribution_graph(hops, origin_idx, dominfo.get("from_domain"))
    write_text(os.path.join(graphs_dir,"attribution.mmd"), mmd1)
    mmd2 = domain_graph(dominfo.get("from_domain"))
    write_text(os.path.join(graphs_dir,"domain.mmd"), mmd2)
    # Reports (simple)
    mark_stage('reports')
    rep_dir = os.path.join(case_dir,"report")
    ensure_dir(rep_dir)
    exec_md = f"> TRANSMITTING SERVER CANDIDATE: **{ip}** — AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\n> *Unverified Received-header candidate; does not establish the original sender or attacker*\n> Recipient MX chain hops marked as [MX-internal].\n\n# Attribution Summary\n\n**Transmitting Server Candidate**: {ip} / AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\n\n**From Domain**: {from_domain}\nRegistrar: {dominfo['from_domain'].get('registrar')}\nCreated: {dominfo['from_domain'].get('created')} (NRD: {dominfo['from_domain'].get('nrd_days')}d)\nNS: {', '.join(dominfo['from_domain'].get('ns',[]))}\nMX: {', '.join(dominfo['from_domain'].get('mx',[]))}\n\n**Decision**: {score['decision']} (score={score['score']})\n"
    exec_md += "\n" + authentication_report(auth)
    exec_md += f"\nAssessment coverage: {score.get('assessment_status', 'partial')}. Missing checks do not establish safety.\n"
    exec_md += f"\nDecision score (before display rounding): {score['decision_score']:.12g}. " \
               f"Thresholds: suspicious={score['thresholds']['suspicious']}, malicious={score['thresholds']['malicious']}. " \
               "Uncalibrated attribution heuristic; not a binary phishing classification.\n"
    exec_md += "\nScore components:\n\n" + '\n'.join(
        f"- {name}: {value:.12g} — {score['component_sources'][name]}" for name, value in score['score_components'].items()) + '\n'
    exec_md += "\n" + "\n".join(f"- {name}: {value['status']}" for name, value in stage_status.items()) + "\n"
    # Add detonation/canary sections if they exist
    det = {}
    can_ips = []
    
    det_summary_path = os.path.join(case_dir,"detonation","summary.json")
    if os.path.exists(det_summary_path):
        det = read_json(det_summary_path) or {}
    
    canary_ips_path = os.path.join(case_dir,"canary_ips.json")
    if os.path.exists(canary_ips_path):
        can_ips = read_json(canary_ips_path) or []
    
    canary_visitors_path = os.path.join(case_dir,"canary_visitors.json")
    canary_visitors = read_json(canary_visitors_path) if os.path.exists(canary_visitors_path) else []
    
    exec_md += "\n" + detonation_box(det) + "\n\n" + canary_box(can_ips, canary_visitors)
    write_text(os.path.join(rep_dir,"executive.md"), exec_md)
    tech_md = ("# Technical Details\n\n## Top-level Header Inventory\n"
        f"- Artifact: header_inventory.json; exact original: input.eml\n"
        f"- Parser-recognized fields: {header_inventory['total_field_count']}; "
        f"inventoried: {header_inventory['inventoried_field_count']}; "
        f"omitted: {header_inventory['omitted_field_count']}; "
        f"limited: {header_inventory['limited_field_count']}\n"
        f"- Extraction status: {header_inventory['status']}. "
        "Ordered raw parser values and derived text; unverified header claims.\n"
        "\n## MIME Header Inventory\n"
        f"- Artifact: mime_header_inventory.json; parser nodes: {mime_header_inventory['total_part_count']}; "
        f"inventoried fields: {mime_header_inventory['inventoried_field_count']}; "
        f"omitted fields: {mime_header_inventory['omitted_field_count']}; status: {mime_header_inventory['status']}\n"
        "- Per-node ordered observations; embedded header claims do not describe the outer sender. Exact original: input.eml.\n"
        "\n## MIME Body Evidence\n"
        f"- Artifact: mime_body_evidence.json; preserved parts: {body_inventory['part_count']}; "
        f"payload bytes: {body_inventory['payload_bytes']}; status: {body_inventory['status']}\n"
        "- Per-part transfer-decoded bytes and derived charset text; exact original: input.eml.\n"
        "\n## Received Path\n")
    for i,h in enumerate(hops, start=1):
        tech_md += f"- Hop {i}: by={h.get('by')} from={h.get('from')} ip={h.get('ip')} date={h.get('date')} helo={h.get('helo')} ptr={h.get('ptr')} skew_s={h.get('skew_s')} fqdn_ok={h.get('fqdn_ok')} helo_ptr_match={h.get('helo_ptr_match')} role={h.get('role')}\n"
    tech_md += "\n## Auth Alignment\n"
    tech_md += json.dumps(auth, indent=2) + "\n"
    tech_md += "\n## Forgery Checks\n"
    tech_md += json.dumps(anomalies, indent=2) + "\n"
    # Include deobfuscation analysis details (if available)
    try:
        tech_md += "\n## Deobfuscation Configuration\n"
        tech_md += f"- deobfuscation_weight: {float(deob_weight)}\n\n"
        tech_md += "## Deobfuscation Analysis\n"
        tech_md += json.dumps(headers.get("deobfuscation_analysis", {}), indent=2) + "\n"
    except Exception:
        tech_md += "\n## Deobfuscation Analysis\nCould not include deobfuscation details.\n"
    # Add Rekor section if anchored
    rekor_anchor_path = os.path.join(case_dir, "evidence", "rekor_anchor.json")
    rekor_proof_path = os.path.join(case_dir, "evidence", "rekor_proof.json")
    if os.path.exists(rekor_anchor_path):
        tech_md += "\n## Rekor\n"
        with open(rekor_anchor_path, "r", encoding="utf-8") as f:
            anchor_data = json.load(f)
        tech_md += f"Entry UUID: {anchor_data.get('entry_uuid')}\n"
        tech_md += f"Log Index: {anchor_data.get('logIndex')}\n"
        tech_md += f"Integrated Time: {anchor_data.get('integratedTime')}\n"
        if os.path.exists(rekor_proof_path):
            with open(rekor_proof_path, "r", encoding="utf-8") as f:
                proof_data = json.load(f)
            tech_md += f"Inclusion verified: {proof_data.get('treeSize') is not None}\n"
        tech_md += "\n"
    # Add attachments section
    if atts:
        tech_md += "\n## Attachments (metadata-only)\n"
        tech_md += "| Filename | Size | MIME | Macro | SHA256 |\n"
        tech_md += "|----------|------|------|-------|--------|\n"
        for att in atts:
            tech_md += f"| {att['filename']} | {att['size']} | {att['mime']} | {'not evaluated' if att.get('ole_macro') is None else 'Yes' if att['ole_macro'] else 'No'} | {att['sha256'][:16]}... |\n"
        tech_md += "\n"
    write_text(os.path.join(rep_dir,"technical.md"), tech_md)
    # STIX
    mark_stage('exports')
    if stix:
        stix_bundle = make_stix(case_id, ip, from_domain, ip_res.get("asn_org",""))
        write_json(os.path.join(rep_dir,"stix.json"), stix_bundle)
    # Abuse package
    if abuse:
        out = generate_abuse_package(case_dir, "it" if lang.startswith("it") else "en")
        # Generate ARF (RFC 5965) and X-ARF packages
        generate_arf_package(case_dir)
        generate_xarf_package(case_dir)
        # create subject file as helper
        subj = f"[Abuse][Phishing] Case {case_id} – Origin {ip}/AS{ip_res.get('asn')} – Domain {from_domain}"
        write_text(os.path.join(case_dir, "package", "subject.txt"), subj)
    print(f"[correlation] {correlations['status']}: {correlations['reason']}")

    # ===============================
    # REPORT FINALE COMPLETO
    # ===============================
    print("\n" + "="*80)
    print("📋 ANALISI COMPLETA - Phishing Attribution Workbench")
    print("="*80)
    print(f"🆔 Case ID: {case_id}")
    print(f"📅 Data analisi: {utc_now_iso()[:19].replace('T', ' ')}")
    print(f"📧 File analizzato: {os.path.basename(eml_path)}")
    print()

    # Server di trasmissione
    print("🌐 CANDIDATO DI TRASMISSIONE DAI RECEIVED (non verificato)")
    print("-" * 40)
    if ip:
        print(f"📍 IP: {ip}")
        print(f"🏢 ASN: AS{ip_res.get('asn', 'N/A')} {ip_res.get('asn_org', 'N/A')}")
        print(f"🌍 Paese: {ip_res.get('cc', 'N/A')} (ASN: {ip_res.get('asn_cc', 'N/A')})")
        print(f"📧 Abuse: {', '.join([c.get('value', '') for c in ip_res.get('abuse', []) if c.get('type') == 'email'])}")
        print(f"⚖️  Reputazione: {origin_out.get('reputation', {}).get('category', 'unknown')} (score: {origin_out.get('reputation', {}).get('score', 0)})")
    else:
        print("❌ IP non identificato")
    print()

    # Infrastruttura attaccante
    print("🎯 INFRASTRUTTURA OSSERVATA E LIMITI DI COPERTURA")
    print("-" * 40)

    # Carica dati dalla detonazione
    c2_infra_path = os.path.join(case_dir, "c2_infrastructure.json")
    if os.path.exists(c2_infra_path):
        c2_infra = read_json(c2_infra_path) or []
        if c2_infra:
            print("📍 INFRASTRUTTURE OSSERVATE (attribuzione non verificata):")
            for i, infra in enumerate(c2_infra[:5], 1):  # Mostra max 5
                ip_addr = infra.get('ip', 'N/A')
                country = infra.get('country', 'N/A')
                asn = infra.get('asn', 'N/A')
                org = infra.get('org', 'N/A')
                if org and isinstance(org, str):
                    org = org.replace('AS', '').strip()
                else:
                    org = 'N/A'
                domain = infra.get('host', 'N/A')
                rep = infra.get('reputation', {}).get('category', 'unknown')

                flag = "🇱🇻" if country == "LV" else "🇹🇷" if country == "TR" else "🇺🇸" if country == "US" else "🌍"
                risk = "rischio non stabilito dalla geografia"

                print(f"  {i}. {flag} {ip_addr} ({country}) - {risk}")
                print(f"     Dominio: {domain}")
                print(f"     ASN: AS{asn} {org}")
                print(f"     Reputazione: {rep}")
                print()
        else:
            print("ℹ️  Nessun endpoint disponibile; questo non stabilisce sicurezza")
    else:
        print("ℹ️  Detonazione esclusa o non disponibile; attribuzione non stabilita")

    # Punteggio e decisione
    print("⚖️  VALUTAZIONE RISCHIO")
    print("-" * 40)
    print(f"📊 Punteggio (prima dell'arrotondamento): {score.get('decision_score', score.get('score', 0)):.12g}/1.00")
    print(f"🎯 Decisione: {score.get('decision', 'N/A')}")
    print(f"📈 Categoria: {score.get('category', 'N/A')}")
    print()

    # Raccomandazioni
    print("🎯 RACCOMANDAZIONI AZIONE")
    print("-" * 40)

    # Raccomandazioni per IP attaccanti
    if os.path.exists(c2_infra_path):
        c2_infra = read_json(c2_infra_path) or []
        if c2_infra:
            print("Contatti registrati per eventuale revisione manuale (nessun invio):")
            for infra in c2_infra[:3]:  # Top 3
                ip_addr = infra.get('ip', '')
                country = infra.get('country', '')
                abuse_contacts = infra.get('abuse_contacts', [])
                if abuse_contacts:
                    abuse_emails = [c.get('value', '') for c in abuse_contacts if c.get('type') == 'email']
                    if abuse_emails:
                        print(f"  • {ip_addr} ({country}): {', '.join(abuse_emails[:2])}")

    # Raccomandazioni generali
    print("\n📋 Azioni consigliate:")
    print("  • Esaminare le evidenze e le verifiche mancanti")
    print("  • Confermare il contesto prima di segnalazioni o blocchi")
    print("  • Verificare integrita dei file e autenticazione dell'email")

    print("\n" + "="*80)
    print(f"💾 Report salvato in: {case_dir}")
    print("📄 File principali: report/executive.md, report/technical.md")
    print("="*80)

    print(f"[trace] case created: {case_dir}")

    # Print beautiful summary
    mark_stage('evidence_seal')
    print_beautiful_summary(case_dir, case_id, score, ip, ip_res, from_domain, dominfo, auth, lang)
    write_json(os.path.join(case_dir, 'execution.json'), {
        'status': 'completed', 'scope': 'offline_local' if no_egress else 'network_enabled', 'elapsed_seconds': time.perf_counter() - started,
        'no_egress': bool(no_egress),
        'skipped_stages': ['detonation', 'network_enrichment', 'rekor_anchor'] if no_egress else [],
        'blocked_operations': violations()[violations_before:],
        'input_kind': 'derived_fixture' if msg.get('X-PAW-Fixture') else 'email',
        'transport_headers_available': bool(headers.get('received')),
        'assessment_status': score.get('assessment_status'),
        'authentication_status': auth.get('status'),
        'not_evaluated': score.get('coverage', {}).get('not_evaluated', []),
        'runtime_limits': json.loads(os.environ.get('PAW_RUNTIME_LIMITS', '{}')),
        'observed_stage_timings': read_progress(os.environ.get('PAW_PROGRESS_PATH', '')).get('stage_timings', []),
    })
    seal_case(case_dir)
    # Rekor anchor (optional)
    if anchor and not no_egress:
        REKOR_URL = os.environ.get('PAW_REKOR_URL', 'https://rekor.sigstore.dev')
        PRIV = os.environ.get('PAW_REKOR_PRIVKEY_PEM')
        PUB = os.environ.get('PAW_REKOR_PUBKEY_PEM')
        if PRIV and PUB:
            try:
                from .rekor import fetch_inclusion_proof
                outp = anchor_case(case_dir, REKOR_URL, PRIV, PUB)
                print(f"[rekor] anchored: {outp}")
                # Fetch inclusion proof
                with open(outp, "r", encoding="utf-8") as f:
                    anchor_data = json.load(f)
                entry_uuid = anchor_data.get("entry_uuid")
                if entry_uuid:
                    proof = fetch_inclusion_proof(REKOR_URL, entry_uuid)
                    proof_path = os.path.join(case_dir, "evidence", "rekor_proof.json")
                    with open(proof_path, "w", encoding="utf-8") as f:
                        json.dump(proof, f, indent=2)
                    print(f"[rekor] proof fetched: {proof_path}")
            except Exception as e:
                print(f"[rekor] anchor failed: {e}")
        else:
            print('[rekor] skipping: set PAW_REKOR_PRIVKEY_PEM and PAW_REKOR_PUBKEY_PEM to use --anchor')

    return case_dir

def print_beautiful_summary(case_dir: str, case_id: str, score: dict, ip: str, ip_res: dict, 
                          from_domain: str, dominfo: dict, auth: dict, lang: str = "en"):
    """Print a beautiful terminal summary using rich library."""
    console = Console()
    
    # Get key findings from analysis
    findings = []
    
    # Check for criminal infrastructure
    criminal_intel = read_json(os.path.join(case_dir, "criminal_intelligence.json")) or {}
    if criminal_intel:
        findings.append("Infrastructure analysis available; actor attribution not established")
    
    # Check attribution matrix for high confidence
    attr_matrix = read_json(os.path.join(case_dir, "attribution_matrix.json")) or {}
    operator_hypothesis = attr_matrix.get("operator_hypothesis", {})
    confidence = operator_hypothesis.get("confidence", 0)
    
    # Check anomalies
    anomalies = read_json(os.path.join(case_dir, "received_anomalies.json")) or {}
    if (anomalies.get('timing_observations') or {}).get('repeated_ip_claims'):
        findings.append('Repeated Received IP claims; relay behavior unverified')
    
    # Check auth failures
    if auth.get("dmarc", {}).get("inferred_result") == "none":
        findings.append("🟡 DMARC policy: none")
    
    # Determine verdict emoji and color
    score_val = score.get("decision_score", score.get("score", 0))
    verdict = f"{score.get('decision', 'Inconclusive')} (heuristic score: {score_val})"
    verdict_color = 'red' if score_val >= 0.72 else 'yellow'
    
    # Get country flag
    cc = ip_res.get("cc", "")
    flag = {"US": "🇺🇸", "DE": "🇩🇪", "RU": "🇷🇺", "CN": "🇨🇳", "IT": "🇮🇹"}.get(cc, "🌍")
    
    # Create the beautiful output
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]PAW Analysis Complete[/bold cyan]",
        title="🐾 PAW - Phishing Attribution Workbench",
        border_style="cyan",
        box=box.DOUBLE
    ))
    
    # Case info table
    table = Table(box=box.SIMPLE)
    table.add_column("Property", style="dim", width=12)
    table.add_column("Value", style="bold")
    table.add_row("Coverage", score.get("assessment_status", "partial"))
    table.add_row("Auth checks", "not independently verified")
    
    table.add_row("Case ID", f"[cyan]{case_id}[/cyan]")
    table.add_row("Verdict", f"[{verdict_color}]{verdict}[/{verdict_color}]")
    
    console.print(table)
    
    # Origin section
    origin_panel = Panel(
        f"IP:  [bold]{ip}[/bold]\n"
        f"ASN: AS{ip_res.get('asn', 'N/A')} ({ip_res.get('asn_org', 'N/A')})\n"
        f"CC:  {flag} {cc}",
        title="📍 Origin",
        border_style="blue"
    )
    console.print(origin_panel)
    
    # Key findings
    if findings:
        findings_text = "\n".join(findings[:4])  # Max 4 findings
        findings_panel = Panel(
            findings_text,
            title="🔍 Key Findings",
            border_style="yellow"
        )
        console.print(findings_panel)
    
    # Operator hypothesis (if high confidence)
    if confidence >= 0.7:
        hypothesis = operator_hypothesis.get("hypothesis", "Analysis in progress")
        hyp_panel = Panel(
            f"{hypothesis}\n\n[bold]Confidence: {int(confidence * 100)}%[/bold]",
            title="🎯 Operator Hypothesis",
            border_style="magenta"
        )
        console.print(hyp_panel)
    
    # Next steps
    next_steps = [
        f"1. Review report: {os.path.join(case_dir, 'report', 'executive.md')}",
        f"2. Verify files: paw verify --case \"{case_dir}\"",
        f"3. Export ZIP: paw export --case \"{case_dir}\" --format zip"
    ]
    if os.path.exists(os.path.join(case_dir, 'report', 'stix.json')):
        next_steps.append(f"STIX availability status (bundle not generated): {os.path.join(case_dir, 'report', 'stix.json')}")
    if os.path.isdir(os.path.join(case_dir, 'package')):
        next_steps.append(f"Abuse package (not sent): {os.path.join(case_dir, 'package')}")
    
    steps_panel = Panel(
        "\n".join(next_steps),
        title="🚀 Next Steps",
        border_style="green"
    )
    console.print(steps_panel)
    
    console.print()

def update_report(case_dir):
    """Unavailable until versioned updates preserve the sealed evidence and coverage."""
    raise RuntimeError('Report update unavailable: create a new analysis case; existing sealed evidence is preserved')


def analyze_compromised_infrastructure(domain: str, ip: str) -> dict:
    """
    Analizza ricorsivamente l'infrastruttura compromessa per trovare collegamenti upstream.
    Questo va oltre il semplice server compromesso per identificare l'intera catena.
    """
    analysis = {
        "infrastructure_chain": [],
        "upstream_connections": [],
        "threat_intelligence": [],
        "risk_assessment": "unknown"
    }

    try:
        # 1. Analisi DNS per sottodomini correlati
        dns_analysis = analyze_dns_infrastructure(domain)
        if dns_analysis:
            analysis["infrastructure_chain"].extend(dns_analysis)

        # 2. Analisi certificati SSL associati
        ssl_analysis = analyze_ssl_certificates(domain, ip)
        if ssl_analysis:
            analysis["infrastructure_chain"].extend(ssl_analysis)

        # 3. Analisi contenuto web per collegamenti nascosti
        web_analysis = analyze_web_content(domain)
        if web_analysis:
            analysis["upstream_connections"].extend(web_analysis)

        # 4. Correlazione con threat intelligence
        ti_analysis = correlate_threat_intelligence(domain, ip)
        if ti_analysis:
            analysis["threat_intelligence"].extend(ti_analysis)

        # 5. Valutazione rischio complessiva
        analysis["risk_assessment"] = assess_infrastructure_risk(analysis)

    except Exception as e:
        analysis["error"] = str(e)

    return analysis if analysis["infrastructure_chain"] or analysis["upstream_connections"] else None


def analyze_dns_infrastructure(domain: str) -> list:
    """Analizza i record DNS per trovare infrastruttura correlata."""
    findings = []

    try:
        import dns.resolver

        # Cerca sottodomini comuni usati negli attacchi
        subdomains = [
            "mail", "smtp", "webmail", "admin", "cpanel", "plesk", "whm",
            "api", "cdn", "static", "assets", "files", "upload", "download",
            "c2", "command", "control", "callback", "beacon", "exfil"
        ]

        for sub in subdomains:
            try:
                answers = dns.resolver.resolve(f"{sub}.{domain}", "A")
                for rdata in answers:
                    findings.append({
                        "type": "dns_subdomain",
                        "subdomain": f"{sub}.{domain}",
                        "ip": str(rdata),
                        "risk": "high" if sub in ["c2", "command", "control", "callback"] else "medium"
                    })
            except:
                pass

        # Cerca record TXT per configurazioni sospette
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            for rdata in txt_records:
                txt_content = str(rdata)
                if any(keyword in txt_content.lower() for keyword in ["spf", "dkim", "dmarc"]):
                    findings.append({
                        "type": "dns_txt_config",
                        "content": txt_content,
                        "risk": "low"
                    })
        except:
            pass

    except ImportError:
        findings.append({
            "type": "dns_error",
            "message": "dnspython not available",
            "risk": "unknown"
        })

    return findings


def analyze_ssl_certificates(domain: str, ip: str) -> list:
    """Analizza certificati SSL per trovare domini correlati."""
    findings = []

    try:
        import ssl
        import socket

        # Connessione SSL per ottenere il certificato
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Estrai Subject Alternative Names (SAN)
                if cert.get("subjectAltName"):
                    for san_type, san_value in cert["subjectAltName"]:
                        if san_type == "DNS" and san_value != domain:
                            findings.append({
                                "type": "ssl_san",
                                "domain": san_value,
                                "risk": "medium"
                            })

                # Controlla issuer per pattern sospetti
                issuer = cert.get("issuer", [])
                issuer_str = str(issuer)
                if any(suspicious in issuer_str.lower() for suspicious in ["letsencrypt", "zerossl"]):
                    findings.append({
                        "type": "ssl_issuer_suspicious",
                        "issuer": issuer_str,
                        "risk": "low"
                    })

    except Exception as e:
        findings.append({
            "type": "ssl_error",
            "message": str(e),
            "risk": "unknown"
        })

    return findings


def analyze_web_content(domain: str) -> list:
    """Analizza il contenuto web per collegamenti upstream."""
    findings = []

    try:
        import requests
        try:
            from bs4 import BeautifulSoup, Comment
        except ImportError:
            findings.append({
                "type": "web_error",
                "message": "beautifulsoup4 not available",
                "risk": "unknown"
            })
            return findings

        import re

        # Scarica la pagina principale
        response = requests.get(f"https://{domain}", timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Cerca collegamenti nascosti in JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Pattern per URL nascosti
                url_patterns = [
                    r'https?://[^\s\'"]+',
                    r'[\w\.-]+\.onion',  # Tor hidden services
                    r'[\w\.-]+\.i2p',   # I2P
                    r'ipfs://[^\s\'"]+', # IPFS
                ]

                for pattern in url_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        if domain not in match:  # Solo collegamenti esterni
                            findings.append({
                                "type": "web_hidden_link",
                                "url": match,
                                "context": "javascript",
                                "risk": "high"
                            })

        # Cerca commenti HTML con informazioni
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            if any(keyword in comment.lower() for keyword in ["c2", "command", "control", "admin"]):
                findings.append({
                    "type": "web_suspicious_comment",
                    "content": str(comment),
                    "risk": "medium"
                })

    except Exception as e:
        findings.append({
            "type": "web_error",
            "message": str(e),
            "risk": "unknown"
        })

    return findings


def correlate_threat_intelligence(domain: str, ip: str) -> list:
    """Correlazione con database di threat intelligence."""
    findings = []

    # Simulazione di controlli threat intelligence
    # In produzione, integrare con API come VirusTotal, AbuseIPDB, etc.

    # Controlli locali basati su pattern noti
    known_malicious_patterns = [
        "c2-server", "phishing-kit", "malware-host",
        "botnet", "ransomware", "exploit"
    ]

    # Controllo reverse DNS per pattern sospetti
    try:
        import socket
        reverse_dns = socket.gethostbyaddr(ip)[0]
        if any(pattern in reverse_dns.lower() for pattern in known_malicious_patterns):
            findings.append({
                "type": "ti_reverse_dns",
                "hostname": reverse_dns,
                "risk": "high"
            })
    except:
        pass

    # Pattern di dominio sospetti
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        findings.append({
            "type": "ti_suspicious_tld",
            "tld": domain.split(".")[-1],
            "risk": "medium"
        })

    return findings


def assess_infrastructure_risk(analysis: dict) -> str:
    """Valuta il rischio complessivo dell'infrastruttura."""
    high_risk_count = sum(1 for item in analysis.get("infrastructure_chain", [])
                         if item.get("risk") == "high")
    high_risk_ti = sum(1 for item in analysis.get("threat_intelligence", [])
                      if item.get("risk") == "high")
    upstream_count = len(analysis.get("upstream_connections", []))

    if high_risk_count >= 2 or high_risk_ti >= 1 or upstream_count >= 3:
        return "critical"
    elif high_risk_count >= 1 or upstream_count >= 1:
        return "high"
    elif len(analysis.get("infrastructure_chain", [])) > 0:
        return "medium"
    else:
        return "low"


def analyze_phishing_kit_content(kit_content: dict) -> dict:
    """
    Analizza il contenuto di un phishing kit per identificare collegamenti C2 upstream.
    Questo va oltre l'analisi statica per trovare pattern dinamici nei toolkit.
    """
    analysis = {
        "c2_servers": [],
        "callback_domains": [],
        "exfiltration_endpoints": [],
        "obfuscated_code": [],
        "suspicious_patterns": [],
        "risk_level": "low"
    }

    try:
        # Analizza HTML content
        if "html" in kit_content:
            html_findings = analyze_html_for_c2(kit_content["html"])
            analysis["c2_servers"].extend(html_findings.get("c2_servers", []))
            analysis["callback_domains"].extend(html_findings.get("callback_domains", []))
            analysis["obfuscated_code"].extend(html_findings.get("obfuscated_code", []))

        # Analizza JavaScript content
        if "javascript" in kit_content:
            js_findings = analyze_javascript_for_c2(kit_content["javascript"])
            analysis["c2_servers"].extend(js_findings.get("c2_servers", []))
            analysis["exfiltration_endpoints"].extend(js_findings.get("exfiltration_endpoints", []))
            analysis["obfuscated_code"].extend(js_findings.get("obfuscated_code", []))

        # Analizza CSS content (può contenere URL nascosti)
        if "css" in kit_content:
            css_findings = analyze_css_for_c2(kit_content["css"])
            analysis["c2_servers"].extend(css_findings.get("c2_servers", []))

        # Pattern analysis complessiva
        all_patterns = analyze_kit_patterns(analysis)
        analysis["patterns"] = all_patterns

        # Valutazione rischio
        analysis["risk_level"] = assess_kit_risk(analysis)

    except Exception as e:
        analysis["error"] = str(e)

    return analysis


def analyze_html_for_c2(html_content: str) -> dict:
    """Analizza HTML per pattern C2."""
    findings = {"c2_servers": [], "callback_domains": [], "obfuscated_code": []}

    try:
        from bs4 import BeautifulSoup, Comment
        import re

        soup = BeautifulSoup(html_content, 'html.parser')

        # Cerca form action URLs
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action and 'http' in action:
                findings["c2_servers"].append({
                    "url": action,
                    "context": "form_action",
                    "risk": "high"
                })

        # Cerca iframe src
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src', '')
            if src and 'http' in src:
                findings["c2_servers"].append({
                    "url": src,
                    "context": "iframe_src",
                    "risk": "high"
                })

        # Cerca commenti con URL
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            urls = re.findall(r'https?://[^\s\'"]+', str(comment))
            for url in urls:
                findings["callback_domains"].append({
                    "url": url,
                    "context": "html_comment",
                    "risk": "medium"
                })

        # Cerca JavaScript inline con pattern sospetti
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                content = script.string
                # Pattern di offuscamento
                if re.search(r'atob\(|eval\(|unescape\(', content):
                    findings["obfuscated_code"].append({
                        "pattern": "javascript_obfuscation",
                        "context": "inline_script",
                        "risk": "high"
                    })

    except Exception as e:
        findings["error"] = str(e)

    return findings


def analyze_javascript_for_c2(js_content: str) -> dict:
    """Analizza JavaScript per pattern C2 e exfiltration."""
    findings = {"c2_servers": [], "exfiltration_endpoints": [], "obfuscated_code": []}

    try:
        import re

        # Pattern semplificato per trovare URL
        url_patterns = [
            r'https?://[^\s\'"]+',  # URL semplice
            r'[\'"](https?://[^\'"]+)[\'"]',  # URL in stringhe
        ]

        all_urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            all_urls.extend(matches)

        # Filtra URL comuni e classifica
        for url in all_urls:
            # Salta CDN e servizi legittimi
            if any(skip in url.lower() for skip in ['google', 'facebook', 'jquery', 'bootstrap', 'cdn']):
                continue

            # Classifica come C2 se contiene pattern sospetti
            if any(suspicious in url.lower() for suspicious in ['cmd', 'exec', 'shell', 'c2', 'control', 'callback']):
                findings["c2_servers"].append({
                    "url": url,
                    "context": "suspicious_url_pattern",
                    "risk": "high"
                })
            elif any(exfil in url.lower() for exfil in ['log', 'track', 'beacon', 'data', 'exfil']):
                findings["exfiltration_endpoints"].append({
                    "url": url,
                    "context": "data_exfiltration",
                    "risk": "high"
                })
            else:
                findings["c2_servers"].append({
                    "url": url,
                    "context": "hardcoded_url",
                    "risk": "medium"
                })

        # Pattern di offuscamento
        obfuscation_indicators = ['eval(', 'atob(', 'btoa(', 'unescape(', 'fromCharCode', '\\x', '\\u']
        for indicator in obfuscation_indicators:
            if indicator in js_content:
                findings["obfuscated_code"].append({
                    "pattern": indicator,
                    "context": "code_obfuscation",
                    "risk": "high"
                })

    except Exception as e:
        findings["error"] = str(e)

    return findings


def analyze_css_for_c2(css_content: str) -> dict:
    """Analizza CSS per URL nascosti."""
    findings = {"c2_servers": []}

    try:
        import re

        # Cerca url() in CSS
        url_pattern = r'url\([\'"]?(https?://[^\'")]+)[\'"]?\)'
        urls = re.findall(url_pattern, css_content, re.IGNORECASE)

        for url in urls:
            findings["c2_servers"].append({
                "url": url,
                "context": "css_url",
                "risk": "low"
            })

    except Exception as e:
        findings["error"] = str(e)

    return findings


def analyze_kit_patterns(kit_content: dict) -> list:
    """Analizza pattern complessivi nel kit."""
    patterns = []

    try:
        all_content = ""
        for content_type, content in kit_content.items():
            if isinstance(content, str):
                all_content += content + "\n"

        # Pattern di campagne note
        campaign_patterns = [
            ("emotet", r'emotet|epoch\d+', "high"),
            ("trickbot", r'trickbot|trickload', "high"),
            ("ryuk", r'ryuk|hermes', "high"),
            ("phishing_generic", r'password|login|verify|account', "medium"),
            ("malware_dropper", r'dropper|loader|shellcode', "high"),
        ]

        for name, pattern, risk in campaign_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                patterns.append({
                    "pattern": name,
                    "regex": pattern,
                    "risk": risk,
                    "context": "content_analysis"
                })

    except Exception as e:
        patterns.append({
            "pattern": "error",
            "error": str(e),
            "risk": "unknown"
        })

    return patterns


def assess_kit_risk(analysis: dict) -> str:
    """Valuta il rischio del phishing kit."""
    c2_count = len(analysis.get("c2_servers", []))
    exfil_count = len(analysis.get("exfiltration_endpoints", []))
    obfuscation_count = len(analysis.get("obfuscated_code", []))
    high_risk_patterns = sum(1 for p in analysis.get("suspicious_patterns", [])
                           if p.get("risk") == "high")

    if exfil_count >= 1 or high_risk_patterns >= 2 or obfuscation_count >= 3:
        return "critical"
    elif c2_count >= 3 or high_risk_patterns >= 1:
        return "high"
    elif c2_count >= 1 or obfuscation_count >= 1:
        return "medium"
    else:
        return "low"


def analyze_kit_patterns(kit_analysis: dict) -> dict:
    """Analizza pattern nel kit per identificare famiglie malware e campagne."""
    patterns = {
        "malware_family": "unknown",
        "campaign_indicators": [],
        "attacker_fingerprint": {},
        "similar_campaigns": []
    }

    try:
        # Pattern di famiglie malware note
        malware_signatures = {
            "phishing_kit_v1": ["login.php", "config.php", "index.html", "jquery.js"],
            "credential_harvester": ["steal.php", "mail.php", "smtp.php"],
            "banking_trojan": ["bank.php", "transfer.php", "balance.php"],
            "ransomware_locker": ["encrypt.php", "decrypt.php", "key.php"],
            "c2_beacon": ["beacon.js", "cmd.php", "shell.php"]
        }

        # Analizza file presenti
        files_found = []
        if "files" in kit_analysis:
            files_found = [f.get("filename", "") for f in kit_analysis["files"]]

        # Identifica famiglia malware
        for family, signatures in malware_signatures.items():
            matches = sum(1 for sig in signatures if any(sig in f for f in files_found))
            if matches >= len(signatures) * 0.6:  # 60% match
                patterns["malware_family"] = family
                break

        # Pattern di campagne
        campaign_patterns = {
            "business_email_compromise": ["invoice", "payment", "wire", "transfer"],
            "credential_theft": ["login", "password", "account", "verify"],
            "tech_support_scam": ["support", "microsoft", "apple", "tech"],
            "investment_scam": ["crypto", "bitcoin", "investment", "profit"]
        }

        # Analizza contenuto per pattern di campagna
        all_content = ""
        if "html_analysis" in kit_analysis:
            all_content += kit_analysis["html_analysis"].get("content", "")
        if "js_analysis" in kit_analysis:
            for finding in kit_analysis["js_analysis"].get("c2_servers", []):
                all_content += finding.get("url", "")

        for campaign, keywords in campaign_patterns.items():
            if any(kw in all_content.lower() for kw in keywords):
                patterns["campaign_indicators"].append(campaign)

        # Fingerprinting attaccante basato su pattern tecnici
        attacker_patterns = {
            "obfuscation_technique": "none",
            "c2_protocol": "http",
            "exfiltration_method": "post",
            "target_industry": "generic"
        }

        # Analizza tecniche di offuscamento
        if "js_analysis" in kit_analysis and kit_analysis["js_analysis"].get("obfuscated_code"):
            obfuscation = kit_analysis["js_analysis"]["obfuscated_code"]
            if any("eval" in str(o) for o in obfuscation):
                attacker_patterns["obfuscation_technique"] = "eval_injection"
            elif any("atob" in str(o) for o in obfuscation):
                attacker_patterns["obfuscation_technique"] = "base64_encoding"

        # Analizza protocollo C2
        if "js_analysis" in kit_analysis:
            c2_servers = kit_analysis["js_analysis"].get("c2_servers", [])
            if any("https" in str(s) for s in c2_servers):
                attacker_patterns["c2_protocol"] = "https"

        patterns["attacker_fingerprint"] = attacker_patterns

        # Campagne simili (basato su fingerprint)
        similar_campaigns = []
        if patterns["malware_family"] != "unknown":
            similar_campaigns.append(f"Campaign using {patterns['malware_family']} toolkit")

        if patterns["campaign_indicators"]:
            for campaign in patterns["campaign_indicators"]:
                similar_campaigns.append(f"Similar {campaign} campaigns")

        patterns["similar_campaigns"] = similar_campaigns

    except Exception as e:
        patterns["error"] = str(e)

    return patterns


def correlate_campaigns(cases_dir: str) -> dict:
    """Legacy evidence.json grouping was not compatible with current cases.

    Neither missing fingerprints nor a shared 'unknown' family establish a
    campaign or actor. Keep the gap explicit until a verified schema and corpus
    support correlation; do not manufacture groups from legacy placeholders.
    """
    return {'status':'unavailable', 'reason':'Cross-case campaign correlation is not validated for the current case schema',
            'campaign_clusters':[], 'attacker_groups':[], 'infrastructure_links':[]}
