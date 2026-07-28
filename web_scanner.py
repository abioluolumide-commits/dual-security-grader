from flask import Flask, render_template_string, request
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def grade_security_headers(headers):
    """Grade security headers out of 100"""
    required_headers = {
        'Strict-Transport-Security': 20,
        'Content-Security-Policy': 20,
        'X-Frame-Options': 15,
        'X-Content-Type-Options': 15,
        'Referrer-Policy': 15,
        'Permissions-Policy': 15
    }
    
    score = 0
    found = []
    missing = []
    
    for header, points in required_headers.items():
        if header in headers:
            score += points
            found.append(header)
        else:
            missing.append(header)
    
    if score >= 90: grade = 'A'
    elif score >= 80: grade = 'B'
    elif score >= 70: grade = 'C'
    elif score >= 60: grade = 'D'
    else: grade = 'F'
    
    return {
        'category': 'Security Headers',
        'score': score,
        'grade': grade,
        'found': found,
        'missing': missing
    }

def grade_proprietary_tech(detected_tech):
    """Grade proprietary tech usage out of 100. Lower vendor lock-in = higher score"""
    vendor_weights = {
        'Cloudflare': -10,
        'AWS': -10,
        'Azure': -10,
        'Google': -10,
        'Akamai': -10,
        'Fastly': -10,
        'Datadog': -5,
        'New Relic': -5,
        'Sentry': -5
    }
    
    base_score = 100
    deductions = 0
    vendors_found = []
    
    for tech in detected_tech:
        for vendor, penalty in vendor_weights.items():
            if vendor.lower() in tech.lower():
                deductions += abs(penalty)
                if vendor not in vendors_found:
                    vendors_found.append(vendor)
    
    score = max(0, base_score - deductions)
    
    if score >= 90: grade = 'A'
    elif score >= 80: grade = 'B'
    elif score >= 70: grade = 'C'
    elif score >= 60: grade = 'D'
    else: grade = 'F'
    
    return {
        'category': 'Proprietary Tech',
        'score': score,
        'grade': grade,
        'vendors_detected': vendors_found,
        'deductions': deductions
    }

def detect_vendors(headers):
    """Auto detect vendors from headers"""
    vendors = []
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    
    if 'server' in h_lower:
        if 'gws' in h_lower['server']: vendors.append('Google')
        if 'cloudflare' in h_lower['server']: vendors.append('Cloudflare')
        if 'akamai' in h_lower['server']: vendors.append('Akamai')
        if 'amazon' in h_lower['server']: vendors.append('AWS')
    
    if 'cf-ray' in h_lower: vendors.append('Cloudflare')
    if 'x-amz' in str(h_lower): vendors.append('AWS')
    if 'x-goog' in str(h_lower): vendors.append('Google')
    
    return list(set(vendors))

def run_audit(headers):
    detected_tech = detect_vendors(headers)
    security_result = grade_security_headers(headers)
    proprietary_result = grade_proprietary_tech(detected_tech)
    return security_result, proprietary_result

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dual Security Grader</title>
    <style>
        body { font-family: Arial; background: #f0f2f5; padding: 20px; }
        .box { background: white; padding: 30px; border-radius: 10px; max-width: 800px; margin: auto; box-shadow: 0 2px 10px #ccc; }
        input { padding: 12px; width: 70%; border: 2px solid #007bff; border-radius: 5px; }
        button { padding: 12px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .result { margin-top: 20px; padding: 20px; border-radius: 8px; background: #f9f9f9; }
        .grade-A { color: green; font-weight: bold; }
        .grade-B { color: #4CAF50; font-weight: bold; }
        .grade-C { color: orange; font-weight: bold; }
        .grade-D { color: #FF9800; font-weight: bold; }
        .grade-F { color: red; font-weight: bold; }
        h1, form { text-align: center; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🔒 Dual Security Grader</h1>
        <p style="text-align:center">Grades Standard Headers AND Proprietary Vendor Usage Separately</p>
        <form method="post">
          <input name="url" placeholder="eportal2.oauife.edu.ng or google.com" required>
          <button>Run Audit</button>
        </form>
        <div class="result">{{result|safe}}</div>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def home():
    result_html = ""
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith('http'):
            url = 'https://' + url
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            r = requests.get(url, timeout=15, verify=False, headers=headers)
            
            sec, prop = run_audit(r.headers)
            
            result_html = f"""
            <h3>Audit Results for: {url}</h3>
            <hr>
            <h4>{sec['category']}: <span class="grade-{sec['grade']}">{sec['score']}/100 - Grade {sec['grade']}</span></h4>
            <b>Found:</b> {', '.join(sec['found']) if sec['found'] else 'None'}<br>
            <b>Missing:</b> {', '.join(sec['missing']) if sec['missing'] else 'None'}
            <hr>
            <h4>{prop['category']}: <span class="grade-{prop['grade']}">{prop['score']}/100 - Grade {prop['grade']}</span></h4>
            <b>Vendors detected:</b> {', '.join(prop['vendors_detected']) if prop['vendors_detected'] else 'None'}<br>
            <b>Deductions:</b> -{prop['deductions']} points for vendor lock-in
            <hr>
            <p><i>Note: Proprietary score is higher when you use less 3rd party vendors</i></p>
            """
        except Exception as e:
            result_html = f"<p style='color:red'>❌ Error: {e}</p>"

    return render_template_string(HTML, result=result_html)

 import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)