import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import time
from utils import find_ip

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("600x400")
        self.root.configure(bg="#282c34")

        # Header
        self.header = tk.Label(self.root, text="Port Scanner", font=("Helvetica", 24, "bold"), bg="#61afef", fg="#282c34", pady=10)
        self.header.pack(fill=tk.X)

        # Frame para entradas
        self.input_frame = tk.Frame(self.root, bg="#282c34")
        self.input_frame.pack(pady=20)

        # Label e Entry para IP/Hostname
        self.label_ip = tk.Label(self.input_frame, text="IP/Hostname:", font=("Helvetica", 14), bg="#282c34", fg="#abb2bf")
        self.label_ip.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.entry_ip = tk.Entry(self.input_frame, width=30, font=("Helvetica", 14))
        self.entry_ip.grid(row=0, column=1, padx=10, pady=10)

        # Label e Entry para Range de Portas
        self.label_ports = tk.Label(self.input_frame, text="Range de Portas (ex: 20-80):", font=("Helvetica", 14), bg="#282c34", fg="#abb2bf")
        self.label_ports.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.entry_ports = tk.Entry(self.input_frame, width=30, font=("Helvetica", 14))
        self.entry_ports.grid(row=1, column=1, padx=10, pady=10)

        # Botão para iniciar a varredura
        self.button_scan = tk.Button(self.root, text="Iniciar Varredura", font=("Helvetica", 14, "bold"), bg="#98c379", fg="#282c34", command=self.start_scan)
        self.button_scan.pack(pady=10)

        # Treeview para exibir resultados
        self.tree = ttk.Treeview(self.root, columns=("Porta", "Status"), show="headings", height=10)
        self.tree.heading("Porta", text="Porta")
        self.tree.heading("Status", text="Status")
        self.tree.column("Porta", anchor="center", width=100)
        self.tree.column("Status", anchor="center", width=100)
        self.tree.pack(pady=20)

        # Barra de rolagem
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

    def start_scan(self):
        ip = self.entry_ip.get()
        port_range = self.entry_ports.get()

        if not ip or not port_range:
            messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
            return

        try:
            start_port, end_port = map(int, port_range.split('-'))
        except ValueError:
            messagebox.showerror("Erro", "Formato de range de portas inválido. Use o formato 'início-fim'.")
            return

        self.tree.delete(*self.tree.get_children())  # Limpar resultados anteriores

        thread = threading.Thread(target=self.scan_ports, args=(ip, start_port, end_port))
        thread.start()

    def scan_ports(self, ip, start_port, end_port):
        for port in range(start_port, end_port + 1):
            result = self.check_port(ip, port)
            self.tree.insert("", "end", values=(port, "Aberta" if result else "Fechada"))

    def check_port(self, ip, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            return result == 0

