#!/bin/bash
# CAPE Mailer v2.3.0 - Syntax Error Fix Script
# ============================================

set -e

echo "🔧 CAPE Mailer v2.3.0 - Syntax Error Fix"
echo "========================================"
echo ""

if [ "$EUID" -ne 0 ]; then
   echo "❌ Bitte als root ausführen: sudo ./fix_syntax_error.sh"
   exit 1
fi

# Backup
echo "📦 Erstelle Backup..."
cp /opt/cape-mailer/bin/cape_mailer.py /opt/cape-mailer/bin/cape_mailer.py.broken_backup
echo "✅ Backup erstellt: cape_mailer.py.broken_backup"

# Patch: Ersetze die fehlerhafte generate_html_report Funktion
echo "🔧 Patche generate_html_report() Funktion..."

python3 << 'ENDPYTHON'
import re

# Lese Datei
with open('/opt/cape-mailer/bin/cape_mailer.py', 'r') as f:
    code = f.read()

# Finde und entferne die alte generate_html_report Funktion
# Sie beginnt mit "def generate_html_report(result: PhishingAnalysisResult) -> str:"
# und endet vor der nächsten "def " Funktion

pattern = r'def generate_html_report\(result: PhishingAnalysisResult\) -> str:.*?(?=\ndef [a-z_]+\()'
match = re.search(pattern, code, re.DOTALL)

if not match:
    print("❌ Funktion nicht gefunden!")
    exit(1)

print(f"✅ Alte Funktion gefunden (Position {match.start()} - {match.end()})")

# Neue Funktion (ohne verschachtelte f-Strings - verwendet Template-Variablen)
new_function = '''def generate_html_report(result: PhishingAnalysisResult) -> str:
    """Generiere HTML-Report für Phishing-Analyse mit OSINT"""
    import json
    from datetime import datetime
    
    verdict_colors = {'malicious': '#dc3545', 'suspicious': '#ffc107', 'likely_clean': '#17a2b8', 'clean': '#28a745', 'unknown': '#6c757d'}
    verdict_icons = {'malicious': '🔴', 'suspicious': '🟡', 'likely_clean': '🟢', 'clean': '🟢', 'unknown': '⚪'}
    color = verdict_colors.get(result.verdict, '#6c757d')
    icon = verdict_icons.get(result.verdict, '⚪')
    
    # Routing HTML
    routing = result.header_analysis.routing_analysis
    routing_hops_html = "".join([
        f"<tr><td>{h.index}</td><td>{h.from_server or 'N/A'}</td><td>{h.to_server or 'N/A'}</td>"
        f"<td>{', '.join(h.ips) if h.ips else 'N/A'}</td><td>{h.tls_version or 'N/A'}</td>"
        f"<td>{h.cipher[:30] if h.cipher else 'N/A'}</td></tr>"
        for h in routing.hops
    ]) or '<tr><td colspan="6"><em>Keine Routing-Info</em></td></tr>'
    
    # Recommendations HTML
    recommendations_html = ""
    for rec in routing.recommendations:
        sev_color = {'high': '#dc3545', 'medium': '#ffc107', 'low': '#28a745'}.get(rec.get('severity'), '#6c757d')
        config_items = "\\n".join([f"{k}: {v}" for k, v in rec.items() if k.startswith('config_')])
        recommendations_html += f'<div class="recommendation" style="border-left:4px solid {sev_color};margin:10px 0;padding:10px;background:#f8f9fa;">'
        recommendations_html += f'<strong style="color:{sev_color};">{rec["system"]}</strong>'
        recommendations_html += f'<p><strong>Issue:</strong> {rec["issue"]}</p>'
        recommendations_html += f'<p><strong>Recommendation:</strong> {rec["recommendation"]}</p>'
        recommendations_html += f'<pre style="background:white;padding:8px;font-size:11px;overflow-x:auto;">{config_items}</pre></div>'
    
    if not recommendations_html:
        recommendations_html = '<p><em>Keine Empfehlungen - System optimal konfiguriert!</em></p>'
    
    # OSINT HTML (korrekt, ohne verschachtelte f-Strings)
    osint_color = '#dc3545' if result.osint_analysis.overall_threat_level in ['critical','high'] else '#ffc107' if result.osint_analysis.overall_threat_level == 'medium' else '#28a745'
    
    osint_threats_html = ""
    if result.osint_analysis.high_confidence_threats:
        osint_threats_html = '<div class="section"><strong>⚠️ High-Confidence Threats:</strong><br>'
        osint_threats_html += "".join([f'<span class="tag tag-danger">{t}</span>' for t in result.osint_analysis.high_confidence_threats])
        osint_threats_html += '</div>'
    
    # IP Table
    ip_rows = []
    for ip in result.osint_analysis.ip_reputations[:10]:
        risk = 'risk-high' if ip.overall_threat_score > 60 else 'risk-medium' if ip.overall_threat_score > 30 else ''
        tags = "".join([f'<span class="tag">{t}</span>' for t in ip.threat_tags]) if ip.threat_tags else '<em>Clean</em>'
        ip_rows.append(f'<tr><td>{ip.ip}</td><td class="{risk}">{ip.overall_threat_score}/100</td><td>{tags}</td></tr>')
    ip_table = "".join(ip_rows) if ip_rows else '<tr><td colspan="3"><em>Keine IPs analysiert</em></td></tr>'
    
    # Domain Table
    domain_rows = []
    for d in result.osint_analysis.domain_reputations[:10]:
        risk = 'risk-high' if d.overall_threat_score > 60 else 'risk-medium' if d.overall_threat_score > 30 else ''
        tags = "".join([f'<span class="tag">{t}</span>' for t in d.threat_tags]) if d.threat_tags else '<em>Clean</em>'
        domain_rows.append(f'<tr><td>{d.domain}</td><td class="{risk}">{d.overall_threat_score}/100</td><td>{tags}</td></tr>')
    domain_table = "".join(domain_rows) if domain_rows else '<tr><td colspan="3"><em>Keine Domains analysiert</em></td></tr>'
    
    # URL Table
    url_rows = []
    for u in result.osint_analysis.url_reputations[:20]:
        risk = 'risk-high' if u.overall_threat_score > 60 else 'risk-medium' if u.overall_threat_score > 30 else ''
        tags = "".join([f'<span class="tag">{t}</span>' for t in u.threat_tags]) if u.threat_tags else '<em>Clean</em>'
        url_short = u.url[:60] + '...' if len(u.url) > 60 else u.url
        url_rows.append(f'<tr><td style="word-break:break-all;">{url_short}</td><td class="{risk}">{u.overall_threat_score}/100</td><td>{tags}</td></tr>')
    url_table = "".join(url_rows) if url_rows else '<tr><td colspan="3"><em>Keine URLs analysiert</em></td></tr>'
    
    # URL Analyse Table
    url_analysis_rows = []
    for u in result.url_analyses[:20]:
        url_short = u.url[:80] + '...' if len(u.url) > 80 else u.url
        reachable = '✅' if u.is_reachable else '❌'
        login = '⚠️' if u.has_login_form else '-'
        typo = f'🚨 {u.typosquatting_target}' if u.is_typosquatting else '-'
        url_analysis_rows.append(f'<tr><td style="word-break:break-all;">{url_short}</td><td>{reachable}</td><td>{login}</td><td>{typo}</td><td>{u.url_risk_score}</td></tr>')
    url_analysis_table = "".join(url_analysis_rows) if url_analysis_rows else '<tr><td colspan="5"><em>Keine URLs gefunden</em></td></tr>'
    
    # Anomalien
    anomalies_html = "".join([f'<span class="tag tag-warning">{a}</span>' for a in result.header_analysis.anomalies]) or '<em>Keine Anomalien erkannt</em>'
    
    # Security Systems
    security_systems_html = "".join([f'<span class="tag">{s}</span>' for s in result.header_analysis.security_systems]) or '<em>Keine erkannt</em>'
    
    # Security Issues
    security_issues_html = ""
    if routing.security_issues:
        security_issues_html = f'<p class="risk-high"><strong>⚠️ Security Issues:</strong> {", ".join(routing.security_issues)}</p>'
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phishing-Analyse Report - {result.analysis_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid {color}; padding-bottom: 10px; }}
        h2, h3 {{ color: #555; margin-top: 30px; }}
        .verdict {{ font-size: 24px; font-weight: bold; color: {color}; padding: 15px; background: #f8f9fa; border-radius: 5px; border-left: 5px solid {color}; }}
        .score {{ font-size: 48px; color: {color}; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .risk-high {{ color: #dc3545; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-low {{ color: #28a745; }}
        .tag {{ display: inline-block; padding: 3px 8px; margin: 2px; background: #e9ecef; border-radius: 3px; font-size: 12px; }}
        .tag-warning {{ background: #fff3cd; color: #856404; }}
        .tag-danger {{ background: #f8d7da; color: #721c24; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; font-size: 12px; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        .info-badge {{ display: inline-block; background: #17a2b8; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-left: 5px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>{icon} Phishing-Analyse Report</h1>
    <div class="verdict">Verdict: {result.verdict.upper()}<span class="score" style="float:right;">{result.overall_risk_score}/100</span></div>
    <p><strong>Analyse-ID:</strong> {result.analysis_id}<br><strong>Zeitstempel:</strong> {result.timestamp}<br><strong>Quelldatei:</strong> {os.path.basename(result.source_file)}</p>

    <h2>📧 Header-Analyse</h2>
    <table>
        <tr><th>Feld</th><th>Wert</th></tr>
        <tr><td>Von</td><td>{result.header_analysis.from_address}</td></tr>
        <tr><td>Display Name</td><td>{result.header_analysis.from_display}</td></tr>
        <tr><td>Betreff</td><td>{result.header_analysis.subject}</td></tr>
        <tr><td>Reply-To</td><td>{result.header_analysis.reply_to or '-'}</td></tr>
        <tr><td>Return-Path</td><td>{result.header_analysis.return_path or '-'}</td></tr>
        <tr><td>Originating IP</td><td>{result.header_analysis.originating_ip or 'Nicht ermittelt'}</td></tr>
    </table>

    <h3>🔐 Authentifizierung <span class="info-badge">Multi-Source</span></h3>
    <table>
        <tr><th>Check</th><th>Ergebnis</th><th>Quelle</th></tr>
        <tr><td>SPF</td><td class="{'risk-high' if result.header_analysis.spf_result in ['fail','softfail','temperror','permerror'] else ''}">{result.header_analysis.spf_result}</td><td>{result.header_analysis.spf_source}</td></tr>
        <tr><td>DKIM</td><td class="{'risk-high' if result.header_analysis.dkim_result == 'fail' else ''}">{result.header_analysis.dkim_result}</td><td>{result.header_analysis.dkim_source}</td></tr>
        <tr><td>DMARC</td><td class="{'risk-high' if result.header_analysis.dmarc_result == 'fail' else ''}">{result.header_analysis.dmarc_result}</td><td>{result.header_analysis.dmarc_source}</td></tr>
    </table>

    <h3>🛡️ Mail-Routing-Analyse <span class="info-badge">TLS/Cipher-Check</span></h3>
    <table>
        <tr><th>#</th><th>From Server</th><th>To Server</th><th>IPs</th><th>TLS</th><th>Cipher</th></tr>
        {routing_hops_html}
    </table>
    <p><strong>TLS Encryption:</strong> {'✅ Ja' if routing.uses_tls else '❌ Nein'} | <strong>ARC Headers:</strong> {'✅ Ja' if routing.has_arc else '❌ Nein'}</p>
    {security_issues_html}

    <h3>⚠️ Anomalien</h3>
    <div class="section">{anomalies_html}</div>

    <h3>🛡️ Security-Systeme in der Kette</h3>
    <div class="section">{security_systems_html}</div>

    <h2>🔧 Security-Recommendations für Mail-Gateway-Tuning</h2>
    {recommendations_html}

    <h2>🔗 URL-Analyse ({len(result.url_analyses)} URLs)</h2>
    <table>
        <tr><th>URL</th><th>Erreichbar</th><th>Login-Form</th><th>Typosquatting</th><th>Score</th></tr>
        {url_analysis_table}
    </table>

    <h2>📝 Inhaltsanalyse</h2>
    <table>
        <tr><th>Indikator</th><th>Wert</th></tr>
        <tr><td>Extrahierte URLs</td><td>{len(result.content_analysis.extracted_urls)}</td></tr>
        <tr><td>IBANs (maskiert)</td><td>{', '.join(result.content_analysis.extracted_ibans) or '-'}</td></tr>
        <tr><td>CEO-Fraud Indikatoren</td><td class="{'risk-high' if result.content_analysis.ceo_fraud_indicators else ''}">{', '.join(result.content_analysis.ceo_fraud_indicators) or '-'}</td></tr>
        <tr><td>Bank-Erwähnungen</td><td>{', '.join(result.content_analysis.bank_mentions) or '-'}</td></tr>
        <tr><td>Urgency-Score</td><td>{result.content_analysis.urgency_score}/100</td></tr>
        <tr><td>Tracking-Pixel</td><td>{'⚠️ Ja' if result.content_analysis.has_tracking_pixels else 'Nein'}</td></tr>
    </table>

    <h2>🔍 OSINT Threat Intelligence <span class="info-badge">v2.3.0</span></h2>
    <div class="verdict" style="border-color:{osint_color};">Threat Level: {result.osint_analysis.overall_threat_level.upper()}<span style="float:right;">{result.osint_analysis.total_threat_indicators} High-Confidence Threats</span></div>
    {osint_threats_html}
    
    <h3>🌐 IP Reputation ({len(result.osint_analysis.ip_reputations)} IPs)</h3>
    <table><tr><th>IP</th><th>Threat Score</th><th>Threat Indicators</th></tr>{ip_table}</table>
    
    <h3>🏷️ Domain Reputation ({len(result.osint_analysis.domain_reputations)} Domains)</h3>
    <table><tr><th>Domain</th><th>Threat Score</th><th>Threat Indicators</th></tr>{domain_table}</table>
    
    <h3>🔗 URL Reputation ({len(result.osint_analysis.url_reputations)} URLs)</h3>
    <table><tr><th>URL</th><th>Threat Score</th><th>Threat Indicators</th></tr>{url_table}</table>

    <h2>🤖 KI-Bewertung</h2>
    <div class="section"><pre>{result.ai_analysis or 'Keine KI-Analyse verfügbar'}</pre></div>

    <h2>🎯 IOCs (MISP-ready)</h2>
    <pre>{json.dumps(result.iocs, indent=2, ensure_ascii=False)}</pre>

    <hr>
    <p style="color:#666;font-size:12px;">Generiert von CAPE Phishing Analyzer v2.3.0 (OSINT Integration)<br>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
</body>
</html>"""
    return html

'''

# Ersetze
code = code[:match.start()] + new_function + code[match.end():]

# Schreibe zurück
with open('/opt/cape-mailer/bin/cape_mailer.py', 'w') as f:
    f.write(code)

print("✅ Funktion ersetzt!")

ENDPYTHON

echo ""
echo "✅ Patch erfolgreich angewendet!"
echo ""
echo "🧪 Teste Syntax..."
sudo -u cape-mailer /opt/cape-mailer/venv/bin/python3 -m py_compile /opt/cape-mailer/bin/cape_mailer.py

if [ $? -eq 0 ]; then
    echo "✅ Syntax OK!"
    echo ""
    echo "🚀 Bereit zum Testen:"
    echo "sudo -u cape-mailer /opt/cape-mailer/venv/bin/python3 /opt/cape-mailer/bin/cape_mailer.py --debug"
else
    echo "❌ Syntax-Fehler bleibt bestehen"
    echo "Restore Backup: sudo cp /opt/cape-mailer/bin/cape_mailer.py.broken_backup /opt/cape-mailer/bin/cape_mailer.py"
fi

