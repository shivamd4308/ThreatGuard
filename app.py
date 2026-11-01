import streamlit as st
import datetime
from agent import analyze_url_with_agent, generate_audit_report

# Page Configuration
st.set_page_config(
    page_title="ThreatGuard - Enterprise Security Auditor",
    page_icon="🛡️",
    layout="wide"
)

# Initialize Session State
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
    choice = st.session_state.example_selectbox
    if "Safe" in choice:
        st.session_state.url_input = "https://www.google.com"
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

st.sidebar.markdown(
    "[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/shivam-dwivedi-437616357?utm_source=share_via&utm_content=profile&utm_medium=member_android)"
)
st.sidebar.markdown(
    "[![GitHub](https://img.shields.io/badge/GitHub-View_Code-black?style=flat&logo=github)](https://github.com/shivamd4308)"
)
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
            "🟢 Verified Safe Portal (Google)", 
            "🟡 Suspicious Banking Verification Gateway", 
            "🔴 Malicious Payload Execution Vector (.xyz)"
        ],
        key="example_selectbox",
        on_change=update_url
    )

    url_input = st.text_input("Enter Target URL for Inspection:", key="url_input", placeholder="https://...")
    
    if st.button("🚀 Execute Deep Threat Audit", type="primary"):
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
        
        report_text = generate_audit_report(url_scanned, analysis)
        st.download_button(
            label="📥 Export Forensic Audit Report",
            data=report_text,
            file_name=f"ThreatGuard_Audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

        # Check if risk score > 50% to show Blacklist management
        if risk_val > 50:
            st.markdown("### 🛑 Infrastructure Containment")
            b_col1, b_col2 = st.columns(2)
            
            with b_col1:
                if st.button("🚨 Add to Threat Blacklist"):
                    exists = any(item['url'] == url_scanned for item in st.session_state.blacklist)
                    if not exists:
                        b_entry = {
                            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "url": url_scanned,
                            "risk": risk_val,
                            "type": analysis.get("risk_type", "Unknown"),
                            "origin": analysis.get("origin_location", "Unknown"),
                            "damage": analysis.get("damage_description", ""),
                            "insights": analysis.get("predictive_insights", "")
                        }
                        st.session_state.blacklist.append(b_entry)
                        st.toast("🚨 Successfully blacklisted!", icon="🚨")
                    else:
                        st.toast("ℹ️ URL is already in blacklist.", icon="⚠️")
                        
            with b_col2:
                if st.button("🗑️ Purge from Blacklist"):
                    initial_len = len(st.session_state.blacklist)
                    st.session_state.blacklist = [item for item in st.session_state.blacklist if item['url'] != url_scanned]
                    if len(st.session_state.blacklist) < initial_len:
                        st.toast("✅ Successfully removed from blacklist!", icon="✅")
                    else:
                        st.toast("ℹ️ URL was not found in blacklist.", icon="⚠️")
        else:
            st.info("ℹ️ Blacklist actions are restricted to links with >50% evaluated risk score.")

# ----------------------------------------------------
# TAB 2: INTELLIGENCE HISTORY LOG
# ----------------------------------------------------
elif app_mode == "📊 Intelligence History Log":
    st.subheader("Audited URLs Intelligence Log")
    st.markdown("Chronological record of all security scans executed during this session.")
    
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
    st.markdown("Manually blacklisted malicious domains and threat indicators.")
    
    if not st.session_state.blacklist:
        st.info("Blacklist repository is currently empty.")
    else:
        for idx, b_item in enumerate(st.session_state.blacklist):
            st.markdown(f"### 🔴 {b_item['url']}")
            st.write(f"**Blacklisted Timestamp:** {b_item['timestamp']}")
            st.write(f"**Risk Score:** {b_item['risk']}% | **Vector:** {b_item['type']} | **Origin:** {b_item['origin']}")
            st.write(f"**Damage Profile:** {b_item['damage']}")
            
            if st.button(f"Remove from Blacklist", key=f"purge_bl_{idx}"):
                st.session_state.blacklist.pop(idx)
                st.toast("✅ Successfully removed from blacklist!", icon="✅")
                st.rerun()
            st.markdown("---")