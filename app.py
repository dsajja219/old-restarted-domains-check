import streamlit as st
import pandas as pd
import dns.resolver
import socket
import tldextract
import ipaddress

# ---------------- Page Config ----------------
st.set_page_config(
    page_title="Durga's SPF rDNS Validator",
    layout="wide"
)

# ---------------- Background & Styles ----------------
st.markdown("""
<style>
body {
    background-image: url("https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=1950&q=80");
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}
.stApp {
    background-color: rgba(255, 255, 255, 0.88);
    padding: 30px;
    border-radius: 16px;
}

table {
    width: 100%;
    border-collapse: collapse;
}
th {
    background-color: #2E8B57;
    color: white;
    text-align: center;
    padding: 12px;
}
td {
    text-align: center;
    padding: 10px;
    vertical-align: top;
    color: #000;
}
</style>
""", unsafe_allow_html=True)

# ---------------- Header ----------------
st.markdown("<h1 style='text-align:center;color:#145A32;'>Durga's SPF rDNS Validator</h1>", unsafe_allow_html=True)

# ---------------- Input ----------------
domains_input = st.text_area(
    "Enter domains (one per line)",
    placeholder="example1.com\nexample2.com",
    height=150
)

# ---------------- Helpers ----------------
def get_main_domain(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain

def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                return txt
    except:
        pass
    return None

def extract_spf_ips(spf, collected=None):
    if collected is None:
        collected = set()

    for part in spf.split():
        if part.startswith("ip4:"):
            try:
                net = ipaddress.ip_network(part.replace("ip4:", ""), strict=False)
                for ip in net:
                    collected.add(str(ip))
            except:
                pass

        elif part.startswith("include:"):
            inc = part.replace("include:", "")
            inc_spf = get_spf_record(inc)
            if inc_spf:
                extract_spf_ips(inc_spf, collected)

    return collected

def last_octet(ip):
    return ip.split(".")[-1]

def validate_rdns(ip, domain):
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except:
        return False, None

    return (
        last_octet(ip) in ptr and
        get_main_domain(domain) in ptr,
        ptr
    )

def validate_fdns(ptr, ip):
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(ptr, None)}
        return ip in ips
    except:
        return False

# ---------------- Action ----------------
if st.button("Validate SPF Domains"):
    domains = [d.strip() for d in domains_input.splitlines() if d.strip()]

    if not domains:
        st.warning("Please enter at least one domain")
    else:
        rows = []

        with st.spinner("Validating SPF, rDNS & fDNS..."):
            for domain in domains:
                spf = get_spf_record(domain)

                if not spf:
                    rows.append({
                        "Domain": domain,
                        "SPF Record": "NOT FOUND",
                        "SPF IPs": "None",
                        "Correct rDNS IPs": "None",
                        "Correct PTR Hostnames": "None",
                        "Wrong rDNS IPs": "None",
                        "Wrong PTR Hostnames": "None",
                        "Strict fDNS Status": "FAIL",
                        "Overall Status": "❌ NO SPF"
                    })
                    continue

                ips = extract_spf_ips(spf)

                correct_ips, correct_ptrs = [], []
                wrong_ips, wrong_ptrs = [], []
                fdns_results = []

                for ip in sorted(ips):
                    rdns_ok, ptr = validate_rdns(ip, domain)
                    if rdns_ok:
                        correct_ips.append(ip)
                        correct_ptrs.append(ptr)
                        fdns_results.append(validate_fdns(ptr, ip))
                    else:
                        wrong_ips.append(ip)
                        wrong_ptrs.append(ptr if ptr else "No PTR")
                        fdns_results.append(False)

                rows.append({
                    "Domain": domain,
                    "SPF Record": spf,
                    "SPF IPs": "<br>".join(sorted(ips)),
                    "Correct rDNS IPs": "<br>".join(correct_ips) if correct_ips else "None",
                    "Correct PTR Hostnames": "<br>".join(correct_ptrs) if correct_ptrs else "None",
                    "Wrong rDNS IPs": "<br>".join(wrong_ips) if wrong_ips else "None",
                    "Wrong PTR Hostnames": "<br>".join(wrong_ptrs) if wrong_ptrs else "None",
                    "Strict fDNS Status": "PASS" if fdns_results and all(fdns_results) else "FAIL",
                    "Overall Status": "✅ VALID" if correct_ips and not wrong_ips and all(fdns_results) else "⚠️ PARTIAL"
                })

        df = pd.DataFrame(rows)

        st.markdown("### 🌱 SPF Validation Results")
        st.markdown(df.to_html(index=False, escape=False), unsafe_allow_html=True)

        st.download_button(
            "Download CSV",
            df.to_csv(index=False),
            file_name="spf_rdns_validation.csv",
            mime="text/csv"
        )

# ---------------- Footer ----------------
st.markdown(
    "<div style='text-align:center;margin-top:25px;color:#145A32;'>Built with ❤️ by Durga</div>",
    unsafe_allow_html=True
)
