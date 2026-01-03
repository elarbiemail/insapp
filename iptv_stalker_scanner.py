import subprocess
import requests
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fonction pour vérifier si une adresse MAC commence par 00:1c:79:
def is_target_mac(mac):
    return mac.lower().startswith("00:1c:79:")

# Fonction pour obtenir l'adresse MAC à partir de l'IP via la table ARP
def get_mac_from_ip(ip):
    try:
        # Exécuter la commande ARP pour obtenir la MAC
        result = subprocess.run(['arp', '-a'], stdout=subprocess.PIPE, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if ip in line:
                # Extraire l'adresse MAC avec une regex
                mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', line, re.IGNORECASE)
                if mac_match:
                    return mac_match.group(0)
    except Exception as e:
        print(f"Erreur lors de la récupération de la MAC pour {ip}: {e}")
    return None

# Fonction pour vérifier si un serveur est un serveur Stalker
def is_stalker_server(ip, port=80):
    try:
        url = f"http://{ip}:{port}/stalker_portal/server/load.php"
        response = requests.get(url, timeout=5)
        # Vérifier la réponse pour détecter un serveur Stalker
        if "Authorization" in response.headers or "stalker" in response.text.lower():
            return True
    except:
        pass
    return False

# Fonction pour scanner une plage d'IPs
def scan_host(ip):
    try:
        # Ping l'IP
        result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            mac = get_mac_from_ip(ip)
            if mac and is_target_mac(mac):
                if is_stalker_server(ip):
                    print(f"[+] Serveur trouvé : {ip}, MAC: {mac}")
                    return ip, mac
    except Exception as e:
        pass
    return None

# Fonction principale
def main():
    base_network = "192.168.1."  # Réseau à scanner
    max_hosts = 254
    hosts = [f"{base_network}{i}" for i in range(1, max_hosts + 1)]

    print("Démarrage du scan...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_host, host): host for host in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                ip, mac = result
                print(f"Serveur Stalker trouvé: {ip}, MAC: {mac}")

if __name__ == "__main__":
    main()