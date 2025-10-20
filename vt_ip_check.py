import requests
import json
import os

# VirusTotal API anahtarı 
API_KEY = "kullanıcı api keyi"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Çıktı dizini oluştur
os.makedirs("responses", exist_ok=True)

def check_ip(ip):
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(VT_URL + ip, headers=headers)
        response.raise_for_status()
        data = response.json()
        # JSON yanıtını kaydet
        with open(f"responses/{ip}.json", "w") as f:
            json.dump(data, f, indent=4)
        # Malicious veya suspicious kontrolü
        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        if malicious > 0 or suspicious > 0:
            with open("malicious_ips.txt", "a") as f:
                f.write(ip + "\n")
    except requests.exceptions.RequestException:
        with open("not_found_ips.txt", "a") as f:
            f.write(ip + "\n")

def main():
    # IP'leri oku
    with open("ips.txt", "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    for ip in ips:
        check_ip(ip)

if __name__ == "__main__":
    main()
