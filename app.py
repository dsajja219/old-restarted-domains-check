import streamlit as st
import pandas as pd
import dns.resolver
import socket
import tldextract

# ---------------- Page Config ----------------
st.set_page_config(
    page_title="Durga's SPF & rDNS Validator",
    layout="wide"
)

# ---------------- Styling ----------------
st.markdown("""
<style>
body {
    background-image: url("https://images.unsplash.com/photo-1501785888041-af3ef285b470");
    background-size: cover;
}
.stApp {
    background-color: rgba(255,255,255,0.9);
    padding: 25px;
    border-radius: 15px;
}
th {
    background-color: #007BFF;
    color: white;
    text-align: center;
}
td {
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ---------------- Header ----------------
st.markdown("<h1 style='text-align:center;'>Durga's SPF & rDNS Validation App</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align:center;'>Check SPF • rDNS • fDNS • Domain ↔ IP Alignment</h4>", unsafe_allow_html=True)

# ---------------- Inputs ----------------
col1, col2 = st.columns(2)

with col1:
    domain = st.text_input("Domain", placeholder="example.com")

with col2:
    ips_input = st.text_input("IPs (comma separated)", placeholder="1.2.3.4, 5.6.7.8")

# ---------------- Helper Functions ----------------
def get_spf(domain):
    try:
        records = dns.resolver.resolve(domain, "TXT")
        for r in records:
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                return txt
    except:
        pass
    return None

def spf_allows_ip(spf, ip):
    if not spf:
        return False
    return ip in spf or "all" in spf

def get_ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def forward_dns_ok(hostname, ip):
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(hostname, None)}
        return ip in ips
    except:
        return False

def same_main_domain(domain, hostname):
    d1 = tldextract.extract(domain)
    d2 = tldextract.extract(hostname)
    return d1.domain == d2.domain and d1.suffix == d2.suffix

# ---------------- Action ----------------
if st.button("Validate SPF & rDNS"):
    if not domain or not ips_input:
        st.warning("Please enter domain and IPs")
    else:
        ips = [i.strip() for i in ips_input.split(",") if i.strip()]
        spf = get_spf(domain)

        rows = []

        for ip in ips:
            ptr = get_ptr(ip)
            spf_status = "PASS" if spf_allows_ip(spf, ip) else "FAIL"

            if ptr:
                fdns = "PASS" if forward_dns_ok(ptr, ip) else "FAIL"
                domain_match = "YES" if same_main_domain(domain, ptr) else "NO"
            else:
                fdns = "FAIL"
                domain_match = "NO"

            if spf_status == "PASS" and fdns == "PASS":
                overall = "✅ VALID"
            elif spf_status == "PASS":
                overall = "⚠️ PARTIAL"
            else:
                overall = "❌ INVALID"

            rows.append({
                "Domain": domain,
                "IP": ip,
                "SPF Record": spf or "Not Found",
                "SPF Status": spf_status,
                "PTR Hostname": ptr or "Missing",
                "Forward DNS": fdns,
                "Domain Match": domain_match,
                "Overall Status": overall
            })

        df = pd.DataFrame(rows)

        st.markdown("### ✅ Validation Results")
        st.markdown(df.to_html(index=False), unsafe_allow_html=True)

        st.download_button(
            "Download CSV",
            df.to_csv(index=False),
            file_name="spf_rdns_report.csv",
            mime="text/csv"
        )

# ---------------- Footer ----------------
st.markdown("<div style='text-align:center;margin-top:20px;'>Built by Durga 🚀</div>", unsafe_allow_html=True)
