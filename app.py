import streamlit as st
import pandas as pd
import dns.resolver
import socket
import tldextract

# ---------------- Page Config ----------------
st.set_page_config(
    page_title="Durga's Domain Auth Validator",
    layout="wide"
)

# ---------------- Styles ----------------
st.markdown("""
<style>
.stApp {
    background-color: #f5f7fa;
    padding: 25px;
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
st.markdown("<h1 style='text-align:center;'>Durga's Domain SPF & rDNS Validator</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align:center;'>Enter a domain → Auto-detect IPs → Validate SPF & rDNS</h4>", unsafe_allow_html=True)

# ---------------- Input ----------------
domain = st.text_input("Enter Domain", placeholder="example.com")

# ---------------- Helper Functions ----------------
def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                return txt
    except:
        pass
    return None

def get_mx_ips(domain):
    ips = set()
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        for r in mx_answers:
            host = str(r.exchange).rstrip(".")
            try:
                host_ips = {i[4][0] for i in socket.getaddrinfo(host, None)}
                ips.update(host_ips)
            except:
                pass
    except:
        pass
    return list(ips)

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
if st.button("Validate Domain"):
    if not domain:
        st.warning("Please enter a domain")
    else:
        with st.spinner("Discovering IPs & validating..."):
            spf = get_spf(domain)
            ips = get_mx_ips(domain)

            results = []

            if not ips:
                st.error("No MX IPs found. Domain cannot send email.")
            else:
                for ip in ips:
                    ptr = get_ptr(ip)

                    if ptr:
                        fdns = "PASS" if forward_dns_ok(ptr, ip) else "FAIL"
                        domain_match = "YES" if same_main_domain(domain, ptr) else "NO"
                    else:
                        fdns = "FAIL"
                        domain_match = "NO"

                    if spf and fdns == "PASS":
                        overall = "✅ VALID"
                    elif spf:
                        overall = "⚠️ PARTIAL"
                    else:
                        overall = "❌ INVALID"

                    results.append({
                        "Domain": domain,
                        "Sending IP": ip,
                        "SPF Record": spf or "Not Found",
                        "PTR Hostname": ptr or "Missing",
                        "Forward DNS": fdns,
                        "Domain Match": domain_match,
                        "Overall Status": overall
                    })

        df = pd.DataFrame(results)

        st.markdown("### ✅ Validation Results")
        st.markdown(df.to_html(index=False), unsafe_allow_html=True)

        st.download_button(
            "Download CSV",
            df.to_csv(index=False),
            file_name="domain_auth_validation.csv",
            mime="text/csv"
        )

# ---------------- Footer ----------------
st.markdown(
    "<div style='text-align:center;margin-top:20px;'>Built by Durga 🚀</div>",
    unsafe_allow_html=True
)
