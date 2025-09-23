import json
import os
import re

# Caminhos
txt_path = "oui.txt"
json_path = "oui.json"

# ---------- Função para normalizar OUI ----------
def normalizar_oui(oui):
    clean = re.sub(r"[^0-9A-Fa-f]", "", oui)  # Remove tudo que não seja hexadecimal
    if len(clean) != 6:
        return None
    return "-".join(clean[i:i+2].upper() for i in range(0, 6, 2))

# ---------- Carrega JSON existente ----------
oui_dict = {}
if os.path.exists(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        try:
            oui_dict = json.load(f)
        except:
            oui_dict = {}

duplicados = []

# ---------- Processa o TXT ----------
with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
    for linha in f:
        linha = linha.strip()
        if not linha:
            continue

        # Divide a linha em duas partes: OUI e fabricante
        partes = linha.split(None, 1)  # divide no primeiro espaço
        if len(partes) < 2:
            continue

        prefixo_raw = partes[0]
        fabricante = partes[1].strip()
        prefixo = normalizar_oui(prefixo_raw)
        if not prefixo:
            continue

        if prefixo in oui_dict:
            duplicados.append(prefixo)
        else:
            oui_dict[prefixo] = fabricante

# ---------- Salva JSON atualizado ----------
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(oui_dict, f, indent=4, ensure_ascii=False)

# ---------- Relatório ----------
print(f"Total de OUIs no JSON: {len(oui_dict)}")
if duplicados:
    print(f"OUIs duplicados ignorados: {duplicados}")
else:
    print("Nenhum OUI duplicado encontrado.")
