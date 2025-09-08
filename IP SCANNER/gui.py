import tkinter as tk
from tkinter import ttk, scrolledtext
from net import obter_ip_mascara, escanear_rede
import threading

# ---------- Função para atualizar resultados em tempo real ----------
def atualizar_resultado(ip, status, progresso):
    barra_progresso['value'] = progresso
    area_analise.config(state='normal')
    if status == "Ativo":
        area_analise.insert(tk.END, f"{ip} - {status}\n", "ativo")
    else:
        area_analise.insert(tk.END, f"{ip} - {status}\n", "inativo")
    area_analise.see(tk.END)
    area_analise.config(state='disabled')


# ---------- Função que inicia o escaneamento ----------
def iniciar_escaneamento():
    botao_escaneamento.config(state='disabled')
    area_analise.config(state='normal')
    area_analise.delete('1.0', tk.END)
    area_analise.config(state='disabled')

    ip_local, mascara = obter_ip_mascara()
    if not ip_local or not mascara:
        painel_direita.config(state='normal')
        painel_direita.delete('1.0', tk.END)
        painel_direita.insert(tk.END, "Erro ao obter IP local ou máscara.\n")
        painel_direita.config(state='disabled')
        botao_escaneamento.config(state='normal')
        return

    label_ip_mascara.config(text=f"IP: {ip_local} | Máscara: {mascara}")

    barra_progresso['value'] = 0

    # Thread para escanear sem travar GUI
    def thread_escaneamento():
        ativos = escanear_rede(ip_local, mascara, callback=atualizar_resultado)

        # Exibe resultados finais no painel direito
        painel_direita.config(state='normal')
        painel_direita.delete('1.0', tk.END)
        painel_direita.insert(tk.END, "--- IPs Ativos ---\n", "final")
        for ip, tipo in ativos:
            painel_direita.insert(tk.END, f"{ip} - {tipo}\n", "final")
        painel_direita.config(state='disabled')
        botao_escaneamento.config(state='normal')

    threading.Thread(target=thread_escaneamento, daemon=True).start()

# ---------- Configuração da janela ----------
janela = tk.Tk()
janela.title("IP SCANNER")
janela.geometry("1280x720")
janela.configure(bg="#f5f5f5")

# ---------- Estilos ----------
style = ttk.Style(janela)
style.theme_use('clam')
style.configure("TButton", font=("Consolas", 14, "bold"), padding=10, foreground="#f5f5f5", background="#27ae60")
style.configure("TProgressbar", thickness=25, troughcolor="#bdc3c7", background="#2ecc71")

# ---------- Topo ----------
topo = tk.Frame(janela, bg="#f5f5f5")
topo.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

titulo = tk.Label(
    topo, text="IP SCANNER", font=("Consolas", 26, "bold"), bg="#f5f5f5", fg="#27ae60"
)
titulo.pack(side=tk.LEFT, padx=10)

botao_escaneamento = ttk.Button(topo, text="Escanear Rede", command=iniciar_escaneamento)
botao_escaneamento.pack(side=tk.LEFT, padx=20)

label_ip_mascara = tk.Label(
    topo, text="IP: --- | Máscara: ---", font=("Consolas", 16, "bold"), bg="#f5f5f5", fg="#2ecc71"
)
label_ip_mascara.pack(side=tk.RIGHT, padx=20)

# ---------- Frames principais ----------
frame_central = tk.Frame(janela, bg="#ecf0f1")
frame_central.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

frame_direita = tk.Frame(janela, bg="#ecf0f1", width=400)
frame_direita.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

# ---------- Título da área de escaneamento ----------
label_escaneamento = tk.Label(
    frame_central, text="Escaneamento de IP", font=("Consolas", 18, "bold"),
    bg="#ecf0f1", fg="#27ae60"
)
label_escaneamento.pack(pady=(0,5))

# ---------- Barra de progresso ----------
barra_progresso = ttk.Progressbar(frame_central, orient='horizontal', length=1000, mode='determinate')
barra_progresso.pack(pady=10)

# ---------- Área de análise ----------
area_analise = scrolledtext.ScrolledText(
    frame_central, width=100, height=35, font=("Consolas", 12),
    state='disabled', bg="#2c3e50", fg="#ecf0f1", insertbackground="#2ecc71"
)
area_analise.pack(pady=10)

# ---------- Título da aba direita ----------
label_ips_ativos = tk.Label(
    frame_direita, text="IPs Ativos", font=("Consolas", 18, "bold"),
    bg="#ecf0f1", fg="#27ae60"
)
label_ips_ativos.pack(pady=(0,5))

# ---------- Painel direito (resultados finais) ----------
painel_direita = scrolledtext.ScrolledText(
    frame_direita, width=50, height=40, font=("Consolas", 12),
    state='disabled', bg="#f5f5f5", fg="#27ae60"
)
painel_direita.pack(pady=10, fill=tk.Y)

# ---------- Tags de cores ----------
area_analise.tag_config("ativo", foreground="#2ecc71")
area_analise.tag_config("inativo", foreground="#e74c3c")
painel_direita.tag_config("final", foreground="#27ae60", font=("Consolas", 12, "bold"))

# ---------- Loop principal ----------
janela.mainloop()
