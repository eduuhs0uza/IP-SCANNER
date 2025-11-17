import subprocess
import re
import json
import platform
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def obter_caminho_recurso(nome_arquivo: str) -> str:
    """
    Retorna o caminho absoluto de um arquivo de recurso (ex: oui.json),
    funcionando tanto no ambiente normal quanto dentro de um .exe
    gerado pelo PyInstaller (--onefile).
    """
    try:
        # Quando empacotado pelo PyInstaller, os arquivos vão para esta pasta temporária
        base = sys._MEIPASS  # type: ignore[attr-defined]
    except Exception:
        # Quando rodando normalmente (python net.py), usa a pasta atual
        base = os.path.abspath(".")

    return os.path.join(base, nome_arquivo)

# ---------- Carrega base de dados OUI ----------
CAMINHO_ARQUIVO_OUI = obter_caminho_recurso("oui.json")

try:
    with open(CAMINHO_ARQUIVO_OUI, "r", encoding="utf-8") as arquivo_oui:
        DICIONARIO_OUI = json.load(arquivo_oui)
except Exception as erro_carregar_oui:
    print(f"Erro ao carregar arquivo OUI.json ({CAMINHO_ARQUIVO_OUI}): {erro_carregar_oui}")
    DICIONARIO_OUI = {}


# ---------- Listar todos os IPs locais disponíveis ----------
def listar_enderecos_rede_locais():
    """
    Retorna uma lista de dicionários com os IPs locais encontrados:

    [
        {"ip": "192.168.0.10", "mascara": "255.255.255.0", "descricao": "192.168.0.10 / 255.255.255.0"},
        {"ip": "10.8.0.2", "mascara": "24", "descricao": "10.8.0.2 /24 (Linux/VPN)"},
        ...
    ]
    """

    lista_enderecos = []

    try:
        sistema_operacional = platform.system()

        if sistema_operacional == "Windows":
            resultado_comando = subprocess.check_output(
                "ipconfig",
                shell=True,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )
            linhas_saida = resultado_comando.splitlines()

            lista_ips = []
            lista_mascaras = []

            for linha in linhas_saida:
                # IPv4
                if "IPv4" in linha:
                    correspondencia_ip = re.search(
                        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
                        linha
                    )
                    if correspondencia_ip:
                        lista_ips.append(correspondencia_ip.group(1))

                # Máscara de Sub-rede (normalmente vem logo depois)
                if "Máscara de Sub-rede" in linha or "Mascara de Sub-rede" in linha:
                    correspondencia_mascara = re.search(
                        r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
                        linha
                    )
                    if correspondencia_mascara:
                        lista_mascaras.append(correspondencia_mascara.group(1))

            # Junta IP com máscara pelo índice
            for indice, endereco_ip in enumerate(lista_ips):
                mascara_rede = lista_mascaras[indice] if indice < len(lista_mascaras) else "255.255.255.0"
                descricao = f"{endereco_ip} / {mascara_rede}"
                lista_enderecos.append({
                    "ip": endereco_ip,
                    "mascara": mascara_rede,
                    "descricao": descricao
                })

        else:
            # Linux: usa 'ip addr'
            resultado_comando = subprocess.check_output(
                "ip addr",
                shell=True,
                text=True
            )

            # Pega linhas do tipo: inet 192.168.0.10/24 ...
            for linha in resultado_comando.splitlines():
                linha = linha.strip()
                if linha.startswith("inet ") and not linha.startswith("inet 127."):
                    correspondencia_ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", linha)
                    if correspondencia_ip:
                        endereco_ip = correspondencia_ip.group(1)
                        prefixo_rede = correspondencia_ip.group(2)
                        descricao = f"{endereco_ip} /{prefixo_rede}"
                        lista_enderecos.append({
                            "ip": endereco_ip,
                            "mascara": prefixo_rede,
                            "descricao": descricao
                        })

    except Exception as erro_listar_ips:
        print(f"Erro ao listar endereços de rede locais: {erro_listar_ips}")

    return lista_enderecos


# ---------- Obter IP local e máscara de rede (primeiro da lista) ----------
def obter_ip_mascara():
    """
    Mantida por compatibilidade: retorna apenas o primeiro IP encontrado.
    Preferir usar 'listar_enderecos_rede_locais' na interface.
    """
    lista_enderecos = listar_enderecos_rede_locais()
    if lista_enderecos:
        endereco = lista_enderecos[0]
        return endereco["ip"], endereco["mascara"]
    return None, None


# ---------- Obter MAC local ----------
def obter_mac_local():
    """
    Retorna o endereço MAC da máquina local (primeira interface encontrada).
    """
    try:
        if platform.system() == "Windows":
            resultado_comando = subprocess.check_output(
                "getmac",
                shell=True,
                text=True
            )
            correspondencia_mac = re.search(
                r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})",
                resultado_comando
            )
            if correspondencia_mac:
                return correspondencia_mac.group(1).upper()
        else:
            resultado_comando = subprocess.check_output(
                "ip link",
                shell=True,
                text=True
            )
            correspondencia_mac = re.search(
                r"link/ether ([0-9a-fA-F:]{17})",
                resultado_comando
            )
            if correspondencia_mac:
                return correspondencia_mac.group(1).upper()

    except Exception as erro_mac:
        print(f"Erro ao obter MAC local: {erro_mac}")

    return "Desconhecido"


# ---------- Identificar fabricante pelo OUI ----------
def identificar_oui(endereco_mac):
    """
    Recebe um MAC e tenta identificar o fabricante pelo prefixo OUI.
    """
    if not endereco_mac or endereco_mac == "Desconhecido":
        return "Desconhecido"

    prefixo_oui = endereco_mac.upper()[0:8].replace(":", "-")  # primeiros 3 bytes
    return DICIONARIO_OUI.get(prefixo_oui, "Desconhecido")


# ---------- Definir tipo de dispositivo baseado no OUI + IP ----------
def definir_tipo_dispositivo(endereco_ip, endereco_ip_local, nome_fabricante_oui):
    """
    Retorna uma descrição do tipo de dispositivo (roteador, celular, PC, etc).
    """
    if endereco_ip == endereco_ip_local:
        return "Dispositivo Local"
    if endereco_ip.endswith(".1"):
        return "Roteador/Switch"

    if nome_fabricante_oui == "Desconhecido":
        return "Host"

    nome_fabricante_minusculo = nome_fabricante_oui.lower()

    # Apple
    if "apple" in nome_fabricante_minusculo:
        return "iPhone / iPad / Mac"

    # Celulares
    if "samsung" in nome_fabricante_minusculo:
        return "Celular Samsung"
    if "huawei" in nome_fabricante_minusculo:
        return "Celular Huawei"
    if "xiaomi" in nome_fabricante_minusculo or "redmi" in nome_fabricante_minusculo:
        return "Celular Xiaomi"
    if "motorola" in nome_fabricante_minusculo or "lenovo" in nome_fabricante_minusculo:
        return "Celular Motorola/Lenovo"
    if ("oppo" in nome_fabricante_minusculo or
        "realme" in nome_fabricante_minusculo or
        "oneplus" in nome_fabricante_minusculo):
        return "Celular Oppo/Realme/OnePlus"

    # Roteadores e switches
    if "tp-link" in nome_fabricante_minusculo or "tplink" in nome_fabricante_minusculo:
        return "Roteador TP-Link"
    if "d-link" in nome_fabricante_minusculo:
        return "Roteador D-Link"
    if "cisco" in nome_fabricante_minusculo:
        return "Roteador Cisco"
    if "zte" in nome_fabricante_minusculo:
        return "Roteador ZTE"

    # Computadores
    if ("intel" in nome_fabricante_minusculo or
        "hewlett" in nome_fabricante_minusculo or
        "dell" in nome_fabricante_minusculo or
        "asus" in nome_fabricante_minusculo or
        "micro-star" in nome_fabricante_minusculo or
        "msi" in nome_fabricante_minusculo):
        return "Computador/Notebook"

    if ("realtek" in nome_fabricante_minusculo or
        "broadcom" in nome_fabricante_minusculo or
        "qualcomm" in nome_fabricante_minusculo):
        return "Placa de Rede (PC/Notebook)"

    # Consoles
    if "xbox" in nome_fabricante_minusculo:
        return "Console Xbox"
    if "sony" in nome_fabricante_minusculo or "playstation" in nome_fabricante_minusculo:
        return "Console PlayStation"
    if "nintendo" in nome_fabricante_minusculo:
        return "Console Nintendo"

    # IoT / Dispositivos inteligentes
    if ("gaoshengda" in nome_fabricante_minusculo or
        "shenzhen" in nome_fabricante_minusculo or
        "semiconductor" in nome_fabricante_minusculo):
        return "Dispositivo IoT"

    return "Host"


# ---------- Obter MAC de um IP via ARP ----------
def obter_mac_arp(endereco_ip):
    """
    Envia um ping e consulta a tabela ARP para obter o MAC do IP informado.
    """
    try:
        if platform.system() == "Windows":
            subprocess.run(
                f"ping -n 1 {endereco_ip}",
                shell=True,
                stdout=subprocess.DEVNULL
            )
            resultado_comando = subprocess.check_output(
                f"arp -a {endereco_ip}",
                shell=True,
                text=True
            )
        else:
            subprocess.run(
                f"ping -c 1 {endereco_ip}",
                shell=True,
                stdout=subprocess.DEVNULL
            )
            resultado_comando = subprocess.check_output(
                f"arp {endereco_ip}",
                shell=True,
                text=True
            )

        correspondencia_mac = re.search(
            r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})",
            resultado_comando
        )
        if correspondencia_mac:
            return correspondencia_mac.group(1).upper()

    except Exception:
        pass

    return "Desconhecido"


# ---------- Escanear rede ----------
def escanear_rede(endereco_ip_local, mascara_rede, funcao_retorno_interface=None):
    """
    Escaneia a rede /24 do IP informado e retorna uma lista de dispositivos ativos:
    [(ip, tipo_dispositivo, nome_oui, mac), ...]
    Também chama 'funcao_retorno_interface' a cada IP processado (se fornecida).
    """
    lista_dispositivos_ativos = []

    partes_ip = endereco_ip_local.split(".")
    base_rede = f"{partes_ip[0]}.{partes_ip[1]}.{partes_ip[2]}."

    def ping_dispositivo(indice_host):
        endereco_ip = f"{base_rede}{indice_host}"
        try:
            if platform.system() == "Windows":
                resultado_ping = subprocess.run(
                    f"ping -n 1 -w 100 {endereco_ip}",
                    shell=True,
                    stdout=subprocess.DEVNULL
                )
            else:
                resultado_ping = subprocess.run(
                    f"ping -c 1 -W 1 {endereco_ip}",
                    shell=True,
                    stdout=subprocess.DEVNULL
                )

            status_ip = "Ativo" if resultado_ping.returncode == 0 else "Inativo"
            endereco_mac = obter_mac_arp(endereco_ip) if status_ip == "Ativo" else "Desconhecido"
            nome_fabricante_oui = identificar_oui(endereco_mac)
            tipo_dispositivo = definir_tipo_dispositivo(endereco_ip, endereco_ip_local, nome_fabricante_oui)

            return (endereco_ip, tipo_dispositivo, nome_fabricante_oui, endereco_mac)

        except Exception:
            return (endereco_ip, "Desconhecido", "Desconhecido", "Desconhecido")

    with ThreadPoolExecutor(max_workers=50) as executor:
        tarefas_futuras = [
            executor.submit(ping_dispositivo, indice_host)
            for indice_host in range(1, 255)
        ]

        for indice_concluido, tarefa_concluida in enumerate(as_completed(tarefas_futuras), start=1):
            ip_dispositivo, tipo_dispositivo, nome_fabricante_oui, endereco_mac = tarefa_concluida.result()
            lista_dispositivos_ativos.append(
                (ip_dispositivo, tipo_dispositivo, nome_fabricante_oui, endereco_mac)
            )

            if funcao_retorno_interface:
                percentual_progresso = int(indice_concluido / 254 * 100)
                status_ip = "Ativo" if endereco_mac != "Desconhecido" else "Inativo"

                funcao_retorno_interface(
                    ip_dispositivo,
                    status_ip,
                    tipo_dispositivo,
                    nome_fabricante_oui,
                    percentual_progresso,
                    endereco_mac
                )

    return lista_dispositivos_ativos
