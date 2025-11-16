import subprocess
import re
import ipaddress
import json
import os
from pythonping import ping
import platform
import random

# ---------- Controle de parada do scan ----------
parar_scan = False


def solicitar_parada():
    """Marca para o escaneamento ser interrompido assim que possível."""
    global parar_scan
    parar_scan = True


def resetar_parada():
    """Reseta o estado de parada para novos escaneamentos."""
    global parar_scan
    parar_scan = False


# ---------- Função para obter IP local e máscara ----------
def obter_ip_mascara():
    try:
        # Por enquanto só Windows
        if platform.system() != "Windows":
            print("Sistema não suportado ainda (apenas Windows).")
            return None, None

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

        # Procura máscara de sub-rede
        for linha in linhas:
            if "Máscara de Sub-rede" in linha or "Subnet Mask" in linha:
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

    # Normaliza: remove separadores e usa primeiros 6 hex (3 bytes)
    limpo = mac.upper().replace(":", "").replace("-", "")
    prefixo = limpo[0:6]
    return OUI_DB.get(prefixo, "Outro")


# ---------- Função auxiliar para obter MAC via ARP ----------
def obter_mac_arp(ip):
    try:
        # Usa lista de argumentos (mais seguro)
        resultado = subprocess.check_output(
            ["arp", "-a", ip],
            text=True
        )
        linhas = resultado.splitlines()
        for linha in linhas:
            if ip in linha:
                partes = linha.split()
                if len(partes) >= 2:
                    return partes[1]
    except Exception:
        return None
    return None


# ---------- Função auxiliar para identificar via Nmap (SO) ----------
def identificar_nmap(ip):
    try:
        resultado = subprocess.check_output(
            ["nmap", "-O", ip],
            text=True,
            stderr=subprocess.DEVNULL
        )
        if "Linux" in resultado:
            return "Roteador/Servidor"
        elif "Windows" in resultado:
            return "Computador"
        elif "iOS" in resultado or "Android" in resultado:
            return "Celular"
    except Exception:
        return "Outro"
    return "Outro"


# ---------- Função para listar portas abertas e riscos básicos ----------
def detectar_vulnerabilidades(ip):
    """
    Scan rápido de portas comuns usando nmap -F e gera um resumo
    simples de possíveis riscos (telnet, ftp, smb, rdp, etc.).
    """
    try:
        # -F = portas mais comuns (mais rápido que scan completo)
        resultado = subprocess.check_output(
            ["nmap", "-F", ip],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        return "Scan de portas não concluído"

    portas_abertas = []
    riscos = []

    # portas que normalmente representam maior risco se expostas
    portas_criticas = {
        "21": "FTP",
        "23": "Telnet",
        "445": "SMB",
        "3389": "RDP",
        "5900": "VNC"
    }

    lendo_tabela = False
    for linha in resultado.splitlines():
        linha = linha.strip()
        if linha.startswith("PORT"):
            # A partir daqui começam as linhas de porta
            lendo_tabela = True
            continue
        if lendo_tabela:
            if not linha:
                break
            partes = linha.split()
            if len(partes) >= 2 and "/" in partes[0]:
                porta_proto = partes[0]        # ex: "80/tcp"
                porta = porta_proto.split("/")[0]
                portas_abertas.append(porta)

                if porta in portas_criticas:
                    riscos.append(f"{porta}/{portas_criticas[porta]}")

    if portas_abertas:
        resumo_portas = ", ".join(portas_abertas)
    else:
        resumo_portas = "nenhuma porta comum aberta"

    if riscos:
        resumo_risco = ", ".join(riscos)
    else:
        resumo_risco = "sem portas críticas comuns"

    return f"Portas: {resumo_portas} | Riscos: {resumo_risco}"


# ---------- Função para escanear rede ----------
def escanear_rede(ip_local, mascara, callback=None):
    global parar_scan
    ativos = []

    try:
        rede = ipaddress.IPv4Network(f"{ip_local}/{mascara}", strict=False)
        hosts = list(rede.hosts())

        # embaralha a lista de IPs (não segue 1,2,3...)
        random.shuffle(hosts)

        total = len(hosts) or 1  # evita divisão por zero

        # Tenta descobrir o gateway (x.x.x.1)
        gateway = ip_local.rsplit(".", 1)[0] + ".1"

        for idx, host in enumerate(hosts, start=1):
            # ⛔ se o usuário apertou "Parar", sai do laço
            if parar_scan:
                break

            host_str = str(host)

            # Ping
            try:
                resposta = ping(host_str, count=1, timeout=1)
                status = "Ativo" if resposta.success() else "Inativo"
            except Exception:
                status = "Inativo"

            descricao = "Outro"
            if status == "Ativo":
                mac = obter_mac_arp(host_str)
                tipo = identificar_dispositivo(mac)

                # Se OUI não identificou, tenta Nmap
                if tipo == "Outro":
                    tipo = identificar_nmap(host_str)

                # Se for o gateway, força tipo Roteador
                if host_str == gateway:
                    tipo = "Roteador"

                # ---- Vulnerabilidades / portas abertas ----
                resumo_vuln = detectar_vulnerabilidades(host_str)

                # texto completo que vai pro painel da direita
                descricao = f"{tipo} | {resumo_vuln}"

                ativos.append((host_str, descricao))

            # Callback de atualização em tempo real
            if callback:
                progresso = int((idx / total) * 100)
                callback(host_str, status, progresso)

    except Exception as e:
        print(f"Erro ao escanear rede: {e}")
    finally:
        # Garante que flag de parada volte ao normal ao final
        parar_scan = False

    return ativos
