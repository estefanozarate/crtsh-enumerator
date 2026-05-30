import requests
import json
import sys
from datetime import datetime

URL = "https://crt.sh/"
def get_subdomains(domain):
    print(f"\n[*] Consultando CT Logs para: {domain}")
    print(f"[*] Fuente: crt.sh\n")

    try:
        response = requests.get(
            URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=30
        )
    except requests.exceptions.Timeout:
        print("[-] Timeout — crt.sh no respondio en 30 segundos")
        return []
    except requests.exceptions.ConnectionError:
        print("[-] Error de conexion — verifica tu internet")
        return []

    if response.status_code != 200:
        print(f"[-] Error HTTP {response.status_code}")
        return []

    try:
        data = response.json()
    except json.JSONDecodeError:
        print("[-] crt.sh no devolvio JSON valido")
        return []
    subdomains = set()
    for cert in data:
        for name in cert["name_value"].split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*") and name != domain:
                subdomains.add(name)

    return sorted(subdomains)


def get_cert_history(domain):
    """Devuelve el historial de certificados con fechas"""
    try:
        response = requests.get(
            URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=30
        )
        data = response.json()
    except Exception:
        return []
    seen_serials = set()
    certs = []
    for cert in data:
        serial = cert.get("serial_number", "")
        if serial not in seen_serials:
            seen_serials.add(serial)
            certs.append({
                "names":      cert["name_value"].replace("\n", ", "),
                "issuer":     cert.get("issuer_name", ""),
                "not_before": cert.get("not_before", ""),
                "not_after":  cert.get("not_after", ""),
            })
    return certs


def print_banner():
    print("=" * 55)
    print("  CT Logs Subdomain Enumerator")
    print("  Fuente: crt.sh (Certificate Transparency Logs)")
    print("=" * 55)


def main():
    print_banner()
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("\n[?] Ingresa el dominio objetivo: ").strip()

    if not domain:
        print("[-] Dominio vacio")
        sys.exit(1)

    subdomains = get_subdomains(domain)

    if not subdomains:
        print("[-] No se encontraron subdominios")
    else:
        print(f"[+] {len(subdomains)} subdominios unicos encontrados:\n")
        for i, sub in enumerate(subdomains, 1):
            print(f"  {i:>3}. {sub}")

    print(f"\n[*] Historial de certificados emitidos:\n")
    history = get_cert_history(domain)

    if not history:
        print("  [-] Sin historial disponible")
    else:
        print(f"  {'Emitido desde':<22} {'Expira':<22} Dominios cubiertos")
        print(f"  {'-'*20:<22} {'-'*20:<22} {'-'*30}")
        for cert in history[:15]: 
            not_before = cert["not_before"][:10] if cert["not_before"] else "?"
            not_after  = cert["not_after"][:10]  if cert["not_after"]  else "?"
            names      = cert["names"][:55] + "..." if len(cert["names"]) > 55 else cert["names"]
            print(f"  {not_before:<22} {not_after:<22} {names}")

        if len(history) > 15:
            print(f"\n  ... y {len(history) - 15} certificados mas en el historial")

    print(f"\n{'=' * 55}")
    print(f"  Dominio:       {domain}")
    print(f"  Subdominios:   {len(subdomains)}")
    print(f"  Certificados:  {len(history)}")
    print(f"  Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 55}\n")


if __name__ == "__main__":
    main()
