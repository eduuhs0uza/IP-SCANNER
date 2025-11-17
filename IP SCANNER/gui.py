import tkinter as tk
from tkinter import ttk
from net import (
    listar_enderecos_rede_locais,
    escanear_rede,
    obter_mac_local,
    obter_caminho_recurso,
)
import threading
from queue import Queue
from PIL import Image, ImageTk

# ---------- CORES E CONSTANTES VISUAIS ----------
COR_FUNDO_JANELA = "#f8f9fa"
COR_VERDE_PRINCIPAL = "#27ae60"
COR_VERDE_CLARO = "#2ecc71"
COR_AZUL_ESCUTO_MENU = "#2c3e50"
COR_CARTAO = "#ffffff"
COR_LINHA_IMPAR = "#f2f5f7"

FONTE_PADRAO = ("Segoe UI", 10)
FONTE_TITULO = ("Segoe UI", 20, "bold")
FONTE_SUBTITULO = ("Segoe UI", 9)
FONTE_SECAO = ("Segoe UI", 14, "bold")

# ---------- FILA E LISTA DE ENDEREÇOS ----------
fila_interface = Queue()
lista_enderecos_locais = []
quantidade_dispositivos_ativos = 0  # contador global


# ---------- ATUALIZAÇÃO DA INTERFACE ----------
def atualizar_resultado_interface(endereco_ip, status_ip, tipo_dispositivo,
                                  nome_fabricante_oui, percentual_progresso, endereco_mac):
    barra_progresso["value"] = percentual_progresso

    # Atualiza/insere linha na árvore de análise
    for linha in arvore_ips_em_analise.get_children():
        if arvore_ips_em_analise.item(linha)["values"][0] == endereco_ip:
            arvore_ips_em_analise.item(linha, values=(endereco_ip, status_ip))
            return

    indice = len(arvore_ips_em_analise.get_children())
    tag_linha = "linha_impar" if indice % 2 else "linha_par"
    arvore_ips_em_analise.insert("", "end", values=(endereco_ip, status_ip), tags=(tag_linha,))


def retorno_thread_seguro(endereco_ip, status_ip, tipo_dispositivo,
                          nome_fabricante_oui, percentual_progresso, endereco_mac):
    fila_interface.put((
        "atualizar_analise",
        endereco_ip,
        status_ip,
        tipo_dispositivo,
        nome_fabricante_oui,
        percentual_progresso,
        endereco_mac
    ))


def processar_fila_interface():
    global quantidade_dispositivos_ativos

    while not fila_interface.empty():
        (tipo_evento,
         valor1,
         valor2,
         valor3,
         valor4,
         valor5,
         valor6) = fila_interface.get()

        if tipo_evento == "atualizar_analise":
            atualizar_resultado_interface(valor1, valor2, valor3, valor4, valor5, valor6)

        elif tipo_evento == "finalizar_lista_ativos":
            lista_dispositivos_ativos = valor2

            arvore_ips_ativos.delete(*arvore_ips_ativos.get_children())
            quantidade_dispositivos_ativos = 0

            for dispositivo in lista_dispositivos_ativos:
                ip_dispositivo, tipo_dispositivo, nome_oui, mac_dispositivo = dispositivo
                if mac_dispositivo != "Desconhecido":
                    indice = len(arvore_ips_ativos.get_children())
                    tag_linha = "linha_impar" if indice % 2 else "linha_par"
                    arvore_ips_ativos.insert(
                        "",
                        "end",
                        values=(ip_dispositivo, tipo_dispositivo, nome_oui, mac_dispositivo),
                        tags=(tag_linha,)
                    )
                    quantidade_dispositivos_ativos += 1

            # Atualiza contador visual
            rotulo_contador_ativos.config(
                text=f"{quantidade_dispositivos_ativos} encontrados"
                if quantidade_dispositivos_ativos > 0
                else "Nenhum dispositivo"
            )

            botao_escanear_rede.config(state="normal")

    janela_principal.after(80, processar_fila_interface)


# ---------- CARREGAR IPs DISPONÍVEIS ----------
def carregar_lista_enderecos_locais():
    global lista_enderecos_locais

    lista_enderecos_locais = listar_enderecos_rede_locais()

    if not lista_enderecos_locais:
        caixa_selecao_ip["values"] = ["Nenhum IP encontrado"]
        caixa_selecao_ip.current(0)
        caixa_selecao_ip.config(state="disabled")
        rotulo_ip_mac_local.config(text="Nenhum IP encontrado")
        return

    descricoes = [endereco["descricao"] for endereco in lista_enderecos_locais]
    caixa_selecao_ip["values"] = descricoes
    caixa_selecao_ip.current(0)

    endereco_mac_local = obter_mac_local()
    endereco_ip_selecionado = lista_enderecos_locais[0]["ip"]
    rotulo_ip_mac_local.config(
        text=f"IP selecionado: {endereco_ip_selecionado}  •  MAC: {endereco_mac_local}"
    )


# ---------- ESCANEAR REDE ----------
def iniciar_escanear_rede():
    if not lista_enderecos_locais:
        return

    indice_selecionado = caixa_selecao_ip.current()
    if indice_selecionado < 0 or indice_selecionado >= len(lista_enderecos_locais):
        return

    endereco_selecionado = lista_enderecos_locais[indice_selecionado]
    endereco_ip_local = endereco_selecionado["ip"]
    mascara_rede = endereco_selecionado["mascara"]

    endereco_mac_local = obter_mac_local()
    rotulo_ip_mac_local.config(
        text=f"IP selecionado: {endereco_ip_local}  •  MAC: {endereco_mac_local}"
    )

    botao_escanear_rede.config(state="disabled")
    arvore_ips_em_analise.delete(*arvore_ips_em_analise.get_children())
    arvore_ips_ativos.delete(*arvore_ips_ativos.get_children())
    barra_progresso["value"] = 0
    rotulo_contador_ativos.config(text="—")

    def tarefa_escanear():
        dispositivos_ativos = escanear_rede(
            endereco_ip_local,
            mascara_rede,
            funcao_retorno_interface=retorno_thread_seguro
        )
        fila_interface.put((
            "finalizar_lista_ativos",
            None,
            dispositivos_ativos,
            None,
            None,
            None,
            None
        ))

    threading.Thread(target=tarefa_escanear, daemon=True).start()


# ---------- TESTE DE VULNERABILIDADE ----------
def executar_teste_vulnerabilidade(evento):
    selecao = arvore_ips_ativos.selection()
    if not selecao:
        return
    item = selecao[0]
    endereco_ip = arvore_ips_ativos.item(item, "values")[0]
    print(f"Iniciando teste de vulnerabilidade em {endereco_ip}...")


# ===========================================================
#   CONSTRUÇÃO DA JANELA
# ===========================================================
janela_principal = tk.Tk()
janela_principal.title("IP-ScanED")
janela_principal.geometry("1280x720")
janela_principal.minsize(1100, 600)
janela_principal.configure(bg=COR_FUNDO_JANELA)

# --- Ícone da janela (barra de título / barra de tarefas) ---
try:
    caminho_icone = obter_caminho_recurso("ipscan.ico")
    janela_principal.iconbitmap(caminho_icone)
except Exception as erro:
    print("Não foi possível definir o ícone da janela:", erro)

# ---------- ESTILOS TTK ----------
estilo = ttk.Style(janela_principal)
estilo.theme_use("clam")

estilo.configure(
    "BotaoPrincipal.TButton",
    font=("Segoe UI", 11, "bold"),
    padding=8,
    foreground="#ffffff",
    background=COR_VERDE_PRINCIPAL,
    borderwidth=0
)
estilo.map(
    "BotaoPrincipal.TButton",
    background=[("active", "#1f8d4d")]
)

estilo.configure(
    "BotaoMenu.TButton",
    font=("Segoe UI", 11, "bold"),
    padding=10,
    foreground="#ffffff",
    background=COR_VERDE_PRINCIPAL,
    borderwidth=0
)
estilo.map(
    "BotaoMenu.TButton",
    background=[("active", "#1f8d4d")]
)

estilo.configure(
    "TProgressbar",
    thickness=16,
    troughcolor="#dfe3e6",
    borderwidth=0,
    background=COR_VERDE_PRINCIPAL
)

estilo.configure(
    "Treeview",
    font=("Segoe UI", 9),
    rowheight=22,
    background="#ffffff",
    fieldbackground="#ffffff",
    borderwidth=0
)
estilo.configure(
    "Treeview.Heading",
    font=("Segoe UI", 9, "bold"),
    background=COR_VERDE_PRINCIPAL,
    foreground="#ffffff"
)

# ---------- CABEÇALHO SUPERIOR ----------
quadro_cabecalho = tk.Frame(janela_principal, bg=COR_AZUL_ESCUTO_MENU, height=70)
quadro_cabecalho.grid(row=0, column=0, columnspan=3, sticky="nsew")
quadro_cabecalho.grid_columnconfigure(0, weight=1)
quadro_cabecalho.grid_columnconfigure(1, weight=0)

# bloco de "logo textual"
quadro_logo_texto = tk.Frame(quadro_cabecalho, bg=COR_AZUL_ESCUTO_MENU)
quadro_logo_texto.grid(row=0, column=0, sticky="w", padx=20, pady=10)

rotulo_titulo_logo = tk.Label(
    quadro_logo_texto,
    text="IP-ScanED",
    font=FONTE_TITULO,
    bg=COR_AZUL_ESCUTO_MENU,
    fg="#ecf0f1"
)
rotulo_titulo_logo.pack(anchor="w")

rotulo_ip_mac_local = tk.Label(
    quadro_cabecalho,
    text="IP selecionado: ---  •  MAC: ---",
    font=("Segoe UI", 10, "bold"),
    bg=COR_AZUL_ESCUTO_MENU,
    fg=COR_VERDE_CLARO
)
rotulo_ip_mac_local.grid(row=0, column=1, sticky="e", padx=20, pady=10)

# ---------- BARRA DE SELEÇÃO DE IP / AÇÃO ----------
quadro_filtros = tk.Frame(janela_principal, bg=COR_FUNDO_JANELA)
quadro_filtros.grid(row=1, column=0, columnspan=2, sticky="ew", padx=15, pady=(10, 0))
quadro_filtros.grid_columnconfigure(0, weight=0)
quadro_filtros.grid_columnconfigure(1, weight=1)
quadro_filtros.grid_columnconfigure(2, weight=0)

rotulo_selecao_ip = tk.Label(
    quadro_filtros,
    text="Selecione o IP para escanear:",
    font=FONTE_PADRAO,
    bg=COR_FUNDO_JANELA,
    fg="#444444"
)
rotulo_selecao_ip.grid(row=0, column=0, sticky="w", padx=(0, 8))

caixa_selecao_ip = ttk.Combobox(
    quadro_filtros,
    state="readonly",
    width=40
)
caixa_selecao_ip.grid(row=0, column=1, sticky="ew", padx=(0, 10))

botao_escanear_rede = ttk.Button(
    quadro_filtros,
    text="Escanear Rede",
    style="BotaoPrincipal.TButton",
    command=iniciar_escanear_rede
)
botao_escanear_rede.grid(row=0, column=2, sticky="e")

# ---------- BARRA DE PROGRESSO ----------
barra_progresso = ttk.Progressbar(
    janela_principal,
    orient="horizontal",
    mode="determinate"
)
barra_progresso.grid(row=2, column=0, columnspan=2, sticky="ew", padx=15, pady=(8, 8))

# ---------- AREA PRINCIPAL ----------
janela_principal.grid_rowconfigure(3, weight=1)
janela_principal.grid_columnconfigure(0, weight=2)
janela_principal.grid_columnconfigure(1, weight=3)
janela_principal.grid_columnconfigure(2, weight=0)

# ----- "CARD" IPs em Análise -----
quadro_card_analise = tk.Frame(janela_principal, bg=COR_CARTAO, bd=0, highlightthickness=1,
                               highlightbackground="#dcdfe3")
quadro_card_analise.grid(row=3, column=0, sticky="nsew", padx=(15, 8), pady=(5, 10))

rotulo_analise = tk.Label(
    quadro_card_analise,
    text="IPs em Análise",
    font=FONTE_SECAO,
    bg=COR_CARTAO,
    fg=COR_VERDE_PRINCIPAL
)
rotulo_analise.pack(anchor="w", padx=12, pady=(10, 5))

frame_arvore_analise = tk.Frame(quadro_card_analise, bg=COR_CARTAO)
frame_arvore_analise.pack(fill="both", expand=True, padx=10, pady=(0, 10))

arvore_ips_em_analise = ttk.Treeview(
    frame_arvore_analise,
    columns=("IP", "Status"),
    show="headings"
)
arvore_ips_em_analise.heading("IP", text="IP")
arvore_ips_em_analise.heading("Status", text="Status")
arvore_ips_em_analise.column("IP", width=100, anchor="center")
arvore_ips_em_analise.column("Status", width=80, anchor="center")

scroll_analise_y = ttk.Scrollbar(
    frame_arvore_analise,
    orient="vertical",
    command=arvore_ips_em_analise.yview
)
arvore_ips_em_analise.configure(yscrollcommand=scroll_analise_y.set)

arvore_ips_em_analise.pack(side="left", fill="both", expand=True)
scroll_analise_y.pack(side="right", fill="y")

arvore_ips_em_analise.tag_configure("linha_par", background="#ffffff")
arvore_ips_em_analise.tag_configure("linha_impar", background=COR_LINHA_IMPAR)

# ----- "CARD" IPs Ativos -----
quadro_card_ativos = tk.Frame(janela_principal, bg=COR_CARTAO, bd=0, highlightthickness=1,
                              highlightbackground="#dcdfe3")
quadro_card_ativos.grid(row=3, column=1, sticky="nsew", padx=(8, 15), pady=(5, 10))

# header do card (título + contador)
frame_header_ativos = tk.Frame(quadro_card_ativos, bg=COR_CARTAO)
frame_header_ativos.pack(fill="x", padx=12, pady=(10, 5))

rotulo_ativos = tk.Label(
    frame_header_ativos,
    text="IPs Ativos",
    font=FONTE_SECAO,
    bg=COR_CARTAO,
    fg=COR_VERDE_PRINCIPAL
)
rotulo_ativos.pack(side="left")

rotulo_contador_ativos = tk.Label(
    frame_header_ativos,
    text="—",
    font=("Segoe UI", 10),
    bg=COR_CARTAO,
    fg="#777777"
)
rotulo_contador_ativos.pack(side="right")

frame_arvore_ativos = tk.Frame(quadro_card_ativos, bg=COR_CARTAO)
frame_arvore_ativos.pack(fill="both", expand=True, padx=10, pady=(0, 10))

arvore_ips_ativos = ttk.Treeview(
    frame_arvore_ativos,
    columns=("IP", "Tipo", "OUI", "MAC"),
    show="headings"
)
arvore_ips_ativos.heading("IP", text="IP")
arvore_ips_ativos.heading("Tipo", text="Tipo")
arvore_ips_ativos.heading("OUI", text="OUI")
arvore_ips_ativos.heading("MAC", text="MAC")
arvore_ips_ativos.column("IP", width=90, anchor="center")
arvore_ips_ativos.column("Tipo", width=140, anchor="center")
arvore_ips_ativos.column("OUI", width=200, anchor="center")
arvore_ips_ativos.column("MAC", width=130, anchor="center")

scroll_ativos_y = ttk.Scrollbar(
    frame_arvore_ativos,
    orient="vertical",
    command=arvore_ips_ativos.yview
)
arvore_ips_ativos.configure(yscrollcommand=scroll_ativos_y.set)

arvore_ips_ativos.pack(side="left", fill="both", expand=True)
scroll_ativos_y.pack(side="right", fill="y")

arvore_ips_ativos.tag_configure("linha_par", background="#ffffff")
arvore_ips_ativos.tag_configure("linha_impar", background=COR_LINHA_IMPAR)

arvore_ips_ativos.bind("<Double-1>", executar_teste_vulnerabilidade)

# ---------- MENU LATERAL ----------
quadro_menu_lateral = tk.Frame(janela_principal, bg=COR_AZUL_ESCUTO_MENU, width=220)
quadro_menu_lateral.grid(row=3, column=2, sticky="ns", pady=(5, 10))
quadro_menu_lateral.grid_propagate(False)

rotulo_menu = tk.Label(
    quadro_menu_lateral,
    text="Menu",
    font=("Segoe UI", 16, "bold"),
    bg=COR_AZUL_ESCUTO_MENU,
    fg="#ffffff"
)
rotulo_menu.pack(pady=(20, 10))

botao_menu_principal = ttk.Button(
    quadro_menu_lateral,
    text="Home",
    style="BotaoMenu.TButton"
)
botao_menu_principal.pack(fill="x", padx=20, pady=5)

botao_menu_teste = ttk.Button(
    quadro_menu_lateral,
    text="Teste Vulnerabilidade",
    style="BotaoMenu.TButton"
)
botao_menu_teste.pack(fill="x", padx=20, pady=5)

# ---------- RODAPÉ COM ASSINATURA ----------
quadro_rodape = tk.Frame(janela_principal, bg="#e3e6ea", height=24)
quadro_rodape.grid(row=4, column=0, columnspan=3, sticky="ew")
quadro_rodape.grid_propagate(False)

rotulo_rodape = tk.Label(
    quadro_rodape,
    text="Desenvolvido por Carlos Eduardo Souza de Lima e Carlos Diego Soares da Silva",
    font=("Segoe UI", 8),
    bg="#e3e6ea",
    fg="#555555"
)
rotulo_rodape.pack(side="right", padx=10, pady=4)

janela_principal.grid_rowconfigure(4, weight=0)

# ---------- INICIALIZAÇÃO ----------
carregar_lista_enderecos_locais()
janela_principal.after(80, processar_fila_interface)
