import subprocess
import re
import ipaddress
import json
import os
from pythonping import ping
import platform

# ---------- Função para obter IP local e máscara ----------
def obter_ip_mascara():
    try:
        resultado = subprocess.check_output("ipconfig", shell=True, text=True)
        linhas = resultado.splitlines()
        ip_local = None
        mascara = None

        # Procura IP local (IPv4)
        for linha in linhas:
            if "IPv4" in linha:
                match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", linha)
                if match:
                    ip_local = match.group(1)
                    break

        # Procura máscara de sub-rede (linha que começa com M)
        for linha in linhas:
            if linha.strip().startswith("M"):
                match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", linha)
                if match:
                    mascara = match.group(1)
                    break

        return ip_local, mascara
    except Exception as e:
        print(f"Erro ao obter IP ou máscara: {e}")
        return None, None

# ---------- Função para carregar banco OUI ----------
def carregar_oui():
    caminho = os.path.join(os.path.dirname(__file__), "oui.json")
    if not os.path.exists(caminho):
        print("Arquivo oui.json não encontrado.")
        return {}
    try:
        with open(caminho, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Erro ao carregar OUI: {e}")
        return {}

OUI_DB = carregar_oui()

# ---------- Função para identificar dispositivo pelo MAC ----------
def identificar_dispositivo(mac):
    if not mac:
        return "Outro"
    prefixo = mac.upper().replace(":", "-")[0:8]
    return OUI_DB.get(prefixo, "Outro")

# ---------- Função auxiliar para obter MAC via ARP ----------
def obter_mac_arp(ip):
    try:
        resultado = subprocess.check_output(f"arp -a {ip}", shell=True, text=True)
        linhas = resultado.splitlines()
        for linha in linhas:
            if ip in linha:
                partes = linha.split()
                if len(partes) >= 2:
                    return partes[1]
    except:
        return None
    return None

# ---------- Função auxiliar para identificar via Nmap ----------
def identificar_nmap(ip):
    try:
        resultado = subprocess.check_output(f"nmap -O {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
        if "Linux" in resultado:
            return "Roteador/Servidor"
        elif "Windows" in resultado:
            return "Computador"
        elif "iOS" in resultado or "Android" in resultado:
            return "Celular"
    except:
        return "Outro"
    return "Outro"

# ---------- Função para escanear rede ----------
def escanear_rede(ip_local, mascara, callback=None):
    ativos = []
    try:
        rede = ipaddress.IPv4Network(f"{ip_local}/{mascara}", strict=False)
        hosts = list(rede.hosts())
        total = len(hosts)

        # Tenta descobrir o gateway
        gateway = ip_local.rsplit('.', 1)[0] + ".1"

        for idx, host in enumerate(hosts, start=1):
            host_str = str(host)
            # Ping
            try:
                resposta = ping(host_str, count=1, timeout=1)
                status = "Ativo" if resposta.success() else "Inativo"
            except:
                status = "Inativo"

            tipo = "Outro"
            if status == "Ativo":
                mac = obter_mac_arp(host_str)
                tipo = identificar_dispositivo(mac)
                if tipo == "Outro":
                    # Usa Nmap se OUI não identificar
                    tipo = identificar_nmap(host_str)
                if host_str == gateway:
                    tipo = "Roteador"

                ativos.append((host_str, tipo))

            # Callback de atualização em tempo real
            if callback:
                progresso = int((idx / total) * 100)
                callback(host_str, status, progresso)


    except Exception as e:
        print(f"Erro ao escanear rede: {e}")
    return ativos
