import os
import json
from urllib.parse import urlparse
from groq import Groq

def get_groq_client():
    """Initializes and returns the Groq client."""
    return Groq()

# List of suspicious TLDs often used in phishing & scams
SUSPICIOUS_TLDS = ['.buzz', '.xyz', '.tk', '.cc', '.top', '.work', '.gq', '.ml', '.cf']

def analyze_url_with_agent(target_url: str):
    """
    Analyzes the target URL using a combination of heuristic checks 
    and Groq LLM agentic workflow for accurate threat detection.
    """
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc.lower()
    path_query = parsed_url.path + "?" + parsed_url.query if parsed_url.query else parsed_url.path
    
    # Heuristic checks
    is_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    has_long_query = len(parsed_url.query) > 20 or ('/' in path_query and len(path_query) > 30 and '-' in path_query)
    
    client = get_groq_client()
    
    system_prompt = """
    You are an advanced Agentic AI Security Auditor. Analyze the target URL for phishing, malware, scam, and threat indicators.
    You must return a valid JSON response with the following exact keys:
    - "risk_score": integer between 0 and 100
    - "classification": string (e.g., "High Risk / Phishing", "Suspicious Link", "Verified Safe Domain")
    - "geo_origin": string (e.g., "United States (US)" or "Unknown")
    - "summary": string (brief professional explanation of the security audit findings)
    
    Strict Rules:
    1. If the domain uses a suspicious or cheap TLD (.buzz, .xyz, .tk, .cc, .top, .work, etc.), the risk_score MUST be at least 85% and classification must be "High Risk / Phishing".
    2. If the URL contains obfuscated parameters, random alphanumeric tokens, or weird redirect structures, classify as "High Risk / Phishing" with risk_score > 85%.
    3. Never rate an unverified or sketchy external redirect link as "Verified Safe Domain". Only legitimate well-known root domains (like google.com, github.com) can be safe.
    """
    
    user_prompt = f"Analyze this target URL for security threats: {target_url}\nDomain: {domain}\nPath/Query: {path_query}"
    
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        
        # Enforce hard heuristic override if TLD is sketchy and LLM missed it
        if is_suspicious_tld and result.get("risk_score", 0) < 80:
            result["risk_score"] = 92
            result["classification"] = "High Risk / Phishing"
            result["summary"] += " [System Override: High-risk suspicious TLD structure detected.]"
            
        return result
    except Exception as e:
        # Fallback mechanism if API rate limits or errors out
        score = 90 if (is_suspicious_tld or has_long_query) else 10
        class_type = "High Risk / Phishing" if score > 50 else "Verified Safe Domain"
        return {
            "risk_score": score,
            "classification": class_type,
            "geo_origin": "United States (US)",
            "summary": f"Fallback heuristic analysis due to API limit: {str(e)}"
        }

def generate_audit_report(target_url: str, analysis_data: dict) -> str:
    """
    Generates a professional markdown security audit report based on the analysis data.
    """
    client = get_groq_client()
    prompt = f"""
    Generate a professional cybersecurity audit report in Markdown format for the target URL: {target_url}
    Analysis Data Provided: {json.dumps(analysis_data)}
    Include clear sections: Executive Summary, Threat Indicators, Infrastructure Analysis, and Recommended Action.
    """
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"# Security Audit Report\n\nError generating report: {str(e)}"
