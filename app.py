import streamlit as st
import datetime
from agent import analyze_url_with_agent, generate_audit_report

# Page Configuration
st.set_page_config(
    page_title="ThreatGuard - Enterprise Security Auditor",
    page_icon="🛡️",
    layout="wide"
)

# Initialize Session State safely
if "history" not in st.session_state:
    st.session_state.history = []

if "blacklist" not in st.session_state:
    st.session_state.blacklist = []

if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None

if "url_input" not in st.session_state:
    st.session_state.url_input = ""

# Callback function to auto-fill URL based on dropdown selection
def update_url():
    choice = st.session_state.get("example_selectbox", "")
    if "Safe" in choice:
        st.session_state.url_input = "https://www.github.com"
    elif "Suspicious" in choice:
        st.session_state.url_input = "http://secure-bank-account-update-login.com"
    elif "Malicious" in choice or "Malware" in choice:
        st.session_state.url_input = "http://malware-payload-dropper-mac-download.xyz/root"
    else:
        st.session_state.url_input = ""

# Sidebar Professional Configuration
st.sidebar.title("🛡️ ThreatGuard Operations")
st.sidebar.markdown("### B.Tech CSE (Cybersecurity)")
st.sidebar.success("AI Intelligence Core Active")

st.sidebar.markdown("---")
app_mode = st.sidebar.selectbox(
    "Navigation Console", 
    ["🔍 Threat Analysis Workbench", "📊 Intelligence History Log", "🚫 Blacklisted Infrastructure"]
)

# Developer Info added in Sidebar
st.sidebar.markdown("---")
st.sidebar.markdown("### 👨‍💻 Developer")
st.sidebar.write("**Shivam Dwivedi**")
st.sidebar.write("B.Tech CSE (Cybersecurity)")
st.sidebar.markdown("---")

# Main Header
st.title("🛡️ ThreatGuard: Agentic AI Security Auditor")
st.markdown("Advanced URL intelligence, threat damage forecasting, and infrastructure origin tracking.")

# ----------------------------------------------------
# TAB 1: THREAT ANALYSIS WORKBENCH
# ----------------------------------------------------
if app_mode == "🔍 Threat Analysis Workbench":
    st.subheader("Target URL Forensic Intelligence Hub")
    
    example_choice = st.selectbox(
        "⚡ Select Benchmark Sample Vector:",
        [
            "-- Custom URL Entry --", 
            "🟢 Verified Safe Portal (GitHub / Wikipedia / Google / SBI / Govt)", 
            "🟡 Suspicious Banking Verification Gateway", 
            "🔴 Malicious Payload Execution Vector (.xyz)"
        ],
        key="example_selectbox",
        on_change=update_url
    )

    url_input = st.text_input("Enter Target URL for Inspection:", key="url_input", placeholder="https://...")
    
    if st.button("🚀 Initialize Threat Inspection", type="primary"):
        if not url_input.strip():
            st.warning("Please provide a valid URL string.")
        else:
            with st.spinner("Deploying AI Agent to inspect headers, reputation, and threat vectors..."):
                analysis = analyze_url_with_agent(url_input)
                st.session_state.current_analysis = analysis
                
                history_entry = {
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "url": url_input,
                    "risk": analysis.get("risk_percentage", 0),
                    "type": analysis.get("risk_type", "Unknown"),
                    "origin": analysis.get("origin_location", "Unknown"),
                    "damage": analysis.get("damage_description", ""),
                    "insights": analysis.get("predictive_insights", "")
                }
                st.session_state.history.insert(0, history_entry)

    # Display results from session state persistence
    if st.session_state.current_analysis:
        analysis = st.session_state.current_analysis
        url_scanned = st.session_state.url_input
        risk_val = analysis.get("risk_percentage", 0)
        
        st.success("Forensic Audit Data Loaded Successfully!")
        
        if risk_val > 50:
            st.error(f"⚠️ HIGH RISK VECTOR IDENTIFIED ({risk_val}%)")
        else:
            st.success(f"✅ SECURE INFRASTRUCTURE DETECTED ({risk_val}%)")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Calculated Risk Score", value=f"{risk_val}%")
        with col2:
            st.markdown(f"**Threat Classification:** `{analysis.get('risk_type')}`")
        with col3:
            st.markdown(f"**Server Geo-Origin:** `🌍 {analysis.get('origin_location')}`")

        st.markdown("---")

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown("### 💥 Granular Damage Assessment")
            st.warning(analysis.get("damage_description"))
        with d_col2:
            st.markdown("### 🔮 Predictive Impact & Consequences")
            st.info(analysis.get("predictive_insights"))

        st.markdown("---")
        
        # Professional Action Controls & Blacklist Integration
        st.subheader("🛡️ Action Controls & Incident Response")
        
        already_blacklisted = any(b['url'] == url_scanned for b in st.session_state.blacklist)
        
        if risk_val >= 50:
            if already_blacklisted:
                st.warning("⚠️ This target URL is already isolated in the Blacklisted Infrastructure database.")
            else:
                if st.button("🔒 Isolate & Quarantine Threat", type="primary"):
                    blacklist_entry = {
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "url": url_scanned,
                        "risk": risk_val,
                        "type": analysis.get("risk_type", "Unknown")
                    }
                    st.session_state.blacklist.insert(0, blacklist_entry)
                    st.toast("Threat successfully isolated and added to security blacklist!", icon="🚨")
                    st.rerun()
        else:
            if st.button("✔️ Authorize & Proceed"):
                st.toast("Infrastructure authorized for safe navigation.", icon="✅")
                st.success("Action Executed: Session cleared for secure interaction.")

        st.markdown("---")
        
        report_text = generate_audit_report(url_scanned, analysis)
        st.download_button(
            label="📥 Export Forensic Audit Report",
            data=report_text,
            file_name=f"ThreatGuard_Audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

# ----------------------------------------------------
# TAB 2: INTELLIGENCE HISTORY LOG
# ----------------------------------------------------
elif app_mode == "📊 Intelligence History Log":
    st.subheader("Audited URLs Intelligence Log")
    if not st.session_state.history:
        st.info("No audit records found. Execute a scan in the workbench.")
    else:
        for idx, item in enumerate(st.session_state.history):
            with st.expander(f"[{item['timestamp']}] {item['url']} — Risk: {item['risk']}% ({item['origin']})"):
                st.write(f"**Threat Vector:** {item['type']}")
                st.write(f"**Server Origin:** {item['origin']}")
                st.write(f"**Damage Potential:** {item['damage']}")
                st.write(f"**Predictive Insights:** {item['insights']}")

# ----------------------------------------------------
# TAB 3: BLACKLISTED INFRASTRUCTURE
# ----------------------------------------------------
elif app_mode == "🚫 Blacklisted Infrastructure":
    st.subheader("Contained Threat Blacklist Database")
    if not st.session_state.blacklist:
        st.info("Blacklist repository is currently empty. Quarantine high-risk links from the Threat Analysis Workbench.")
    else:
        if st.button("⚠️ Purge Blacklist Database"):
            st.session_state.blacklist = []
            st.rerun()
            
        st.markdown("---")
        for idx, b_item in enumerate(list(st.session_state.blacklist)):
            col_info, col_action = st.columns([4, 1])
            with col_info:
                st.markdown(f"### 🔴 {b_item['url']}")
                st.write(f"**Quarantined Timestamp:** {b_item['timestamp']} | **Risk Score:** {b_item['risk']}% | **Vector:** {b_item['type']}")
            with col_action:
                st.write("") # spacing
                if st.button("♻️ Restore", key=f"restore_{idx}_{b_item['url']}"):
                    st.session_state.blacklist = [item for item in st.session_state.blacklist if item['url'] != b_item['url']]
                    st.toast(f"Successfully restored domain from blacklist!", icon="✅")
                    st.rerun()
            st.markdown("---")
