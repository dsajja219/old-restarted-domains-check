import streamlit as st
import pandas as pd
import dns.resolver
import socket
import tldextract

# ---------------- Page Config ----------------
st.set_page_config(
    page_title="Durga's Domain DNS Validator",
    layout="wide"
)

# ---------------- Styling ----------------
st.markdown("""
<style>
.stApp {
    background-color: #f4f6f9;
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
st.markdown("<h1 style='text-align:center;'>Durga's Strict DNS Validator</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='text-align:center;'>SPF + Strict rDNS + fDNS (One row per domain)</h4>", unsafe_allow_html=True)

# ---------------- Input ----------------
domains_input = st.text_area(
    "Enter domains (one per line)",
    placeholder="bedrockdealguide.com\nexample.com",
    height=150
)

# ---------------- Helper Functions ----------------
def get_main_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain

def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                return True
    except:
        pass
    return False

def get_mx_ips(domain):
    ips = set()
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for r in answers:
            host = str(r.exchange).rstrip(".")
            try:
                host_ips = {i[4][0] for i in socket.getaddrinfo(host, None)}
                ips.update(host_ips)
            except:
                pass
    except:
        pass
    return list(ips)

def last_octet(ip):
    return ip.split(".")[-1]

def validate_rdns(ip, domain):
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except:
        return False, None

    octet_ok = last_octet(ip) in ptr
    domain_ok = ptr.endswith(get_main_domain(domain))

    return octet_ok and domain_ok, ptr

def validate_fdns(ptr, ip):
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(ptr, None)}
        return ip in ips
    except:
        return False

# ---------------- Action ----------------
if st.button("Validate Domains"):
    domains = [d.strip() for d in domains_input.splitlines() if d.strip()]

    if not domains:
        st.warning("Please enter at least one domain")
    else:
        rows = []

        with st.spinner("Validating domains..."):
            for domain in domains:
                spf_ok = get_spf(domain)
                ips = get_mx_ips(domain)

                correct_ips = []
                correct_ptrs = []
                wrong_ips = []
                wrong_ptrs = []

                fdns_results = []

                for ip in ips:
                    rdns_ok, ptr = validate_rdns(ip, domain)

                    if rdns_ok:
                        correct_ips.append(ip)
                        correct_ptrs.append(ptr)
                        fdns_results.append(validate_fdns(ptr, ip))
                    else:
                        wrong_ips.append(ip)
                        wrong_ptrs.append(ptr if ptr else "No PTR")
                        fdns_results.append(False)

                # Overall verdict
                if ips and spf_ok and not wrong_ips and all(fdns_results):
                    overall = "✅ VALID"
                elif spf_ok:
                    overall = "⚠️ PARTIAL"
                else:
                    overall = "❌ INVALID"

                rows.append({
                    "Domain": domain,
                    "MX IPs": ", ".join(ips) if ips else "None",
                    "SPF Present": "YES" if spf_ok else "NO",
                    "Correct rDNS IPs": ", ".join(correct_ips) if correct_ips else "None",
                    "Correct PTR Hostnames": ", ".join(correct_ptrs) if correct_ptrs else "None",
                    "Wrong rDNS IPs": ", ".join(wrong_ips) if wrong_ips else "None",
                    "Wrong PTR Hostnames": ", ".join(wrong_ptrs) if wrong_ptrs else "None",
                    "Strict fDNS Status": "PASS" if fdns_results and all(fdns_results) else "FAIL",
                    "Overall Status": overall
                })

        df = pd.DataFrame(rows)

        st.markdown("### ✅ Validation Results")
        st.markdown(df.to_html(index=False), unsafe_allow_html=True)

        st.download_button(
            "Download CSV",
            df.to_csv(index=False),
            file_name="strict_dns_validation.csv",
            mime="text/csv"
        )

# ---------------- Footer ----------------
st.markdown(
    "<div style='text-align:center;margin-top:20px;'>Built with ❤️ by Durga</div>",
    unsafe_allow_html=True
)
