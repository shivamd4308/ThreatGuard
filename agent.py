import re
from urllib.parse import urlparse

# Verified Safe Domains (0% Risk - Must be HTTPS and trusted)
SAFE_DOMAINS = [
    'google.com', 'bing.com', 'yahoo.com', 'github.com', 'python.org', 
    'stackoverflow.com', 'geeksforgeeks.org', 'chatgpt.com', 'streamlit.app',
    'wikipedia.org', 'india.gov.in', 'aksuniversity.ac.in', 'amazon.in',
    'youtube.com', 'linkedin.com', 'instagram.com', 'whatsapp.com'
]

# Suspicious Banking & Verification Gateways (75% Risk)
SUSPICIOUS_BANKING_URLS = [
    'secure-bank-account-update-login.com',
    'sbi-netbanking-verify-kyc.net',
    'hdfc-secure-account-unlock.org',
    'icici-netbanking-login-verify.com'
]

# Malicious Payloads & Malware Droppers (93% Risk)
MALWARE_URLS = [
    'malware-payload-dropper-mac-download.xyz',
    'free-apk-mod-game-download.top',
    'win-activation-crack-tool-free.cc'
]

# Advanced Phishing, KBC & Giveaways Keywords / TLDs (95% Risk)
SUSPICIOUS_TLDS = ['.buzz', '.xyz', '.tk', '.cc', '.top', '.work', '.gq', '.ml', '.cf', '.online', '.site', '.icu', '.club']
SCAM_KEYWORDS = ['kbc', 'lottery', 'winner', 'iphone', 'giveaway', 'prize', 'claim', 'reward', 'cashback', 'free-gift', 'whatsapp-gold', 'neverssl']

def analyze_url_with_agent(target_url: str):
    """
    Trained URL analysis engine ensuring HTTP/Insecure links go straight to high risk.
    """
    try:
        if not

