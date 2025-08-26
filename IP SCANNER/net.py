import subprocess
import re

# Executa o comando ipconfig e guarda o resultado
resultado = subprocess.check_output("ipconfig", shell=True, text=True)

# Divide em blocos por adaptador (duas quebras de linha)
blocos = resultado.split('\r\n\r\n')

ip_local = None
mascara = None

for bloco in blocos:
    ip_match = re.search(r"IPv4.*?:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", bloco)
    if ip_match:
        ip_local = ip_match.group(1)
        # Procura a linha que começa com "M" e contém um IP
        for linha in bloco.splitlines():
            if linha.strip().startswith("M"):
                mascara_match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", linha)
                if mascara_match:
                    mascara = mascara_match.group(1)
                    break
        break

print("IP Local:", ip_local)
print("Máscara de Sub-rede:", mascara)

# Separando octetos em listas de inteiros
ip_octetos = [int(o) for o in ip_local.split('.')]
mascara_octetos = [int(o) for o in mascara.split('.')]  

