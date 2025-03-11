import subprocess
import socket
import speedtest
import platform
import psutil
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

class NetDiag:
    def __init__(self, master):
        self.master = master
        master.title("NetDiag - Network Diagnostic Tool")
        master.geometry("600x400")

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        self.create_ping_tab()
        self.create_dns_tab()
        self.create_speed_tab()
        self.create_info_tab()

    def create_ping_tab(self):
        ping_frame = ttk.Frame(self.notebook)
        self.notebook.add(ping_frame, text="Ping Test")

        ttk.Label(ping_frame, text="Enter website or IP:").pack(pady=5)
        self.ping_entry = ttk.Entry(ping_frame, width=40)
        self.ping_entry.pack(pady=5)
        self.ping_entry.insert(0, "google.com")

        ttk.Button(ping_frame, text="Run Ping Test", command=self.run_ping_test).pack(pady=10)

        self.ping_result = scrolledtext.ScrolledText(ping_frame, width=70, height=10)
        self.ping_result.pack(pady=10)

    def create_dns_tab(self):
        dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(dns_frame, text="DNS Lookup")

        ttk.Label(dns_frame, text="Enter domain name:").pack(pady=5)
        self.dns_entry = ttk.Entry(dns_frame, width=40)
        self.dns_entry.pack(pady=5)
        self.dns_entry.insert(0, "python.org")

        ttk.Button(dns_frame, text="Lookup DNS", command=self.run_dns_lookup).pack(pady=10)

        self.dns_result = scrolledtext.ScrolledText(dns_frame, width=70, height=10)
        self.dns_result.pack(pady=10)

    def create_speed_tab(self):
        speed_frame = ttk.Frame(self.notebook)
        self.notebook.add(speed_frame, text="Speed Test")

        ttk.Button(speed_frame, text="Run Speed Test", command=self.run_speed_test).pack(pady=10)

        self.speed_result = scrolledtext.ScrolledText(speed_frame, width=70, height=10)
        self.speed_result.pack(pady=10)

    def create_info_tab(self):
        info_frame = ttk.Frame(self.notebook)
        self.notebook.add(info_frame, text="Network Info")

        ttk.Button(info_frame, text="Get Network Info", command=self.get_network_info).pack(pady=10)

        self.info_result = scrolledtext.ScrolledText(info_frame, width=70, height=15)
        self.info_result.pack(pady=10)

    def run_ping_test(self):
        def ping():
            target = self.ping_entry.get()
            command = ["ping", "-n", "4", target] if platform.system().lower() == "windows" else ["ping", "-c", "4", target]
            result = subprocess.run(command, capture_output=True, text=True)
            self.ping_result.delete(1.0, tk.END)
            self.ping_result.insert(tk.END, result.stdout)
        threading.Thread(target=ping).start()

    def run_dns_lookup(self):
        def dns_lookup():
            domain = self.dns_entry.get()
            try:
                ip = socket.gethostbyname(domain)
                result = f"Domain: {domain}\nIP Address: {ip}"
            except socket.gaierror:
                result = f"Could not resolve the domain: {domain}"
            self.dns_result.delete(1.0, tk.END)
            self.dns_result.insert(tk.END, result)
        threading.Thread(target=dns_lookup).start()

    def run_speed_test(self):
        def speed_test():
            self.speed_result.delete(1.0, tk.END)
            self.speed_result.insert(tk.END, "Running speed test. This may take a minute...\n")
            st = speedtest.Speedtest()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            ping = st.results.ping
            result = f"Download Speed: {download_speed:.2f} Mbps\n"
            result += f"Upload Speed: {upload_speed:.2f} Mbps\n"
            result += f"Ping: {ping:.2f} ms"
            self.speed_result.delete(1.0, tk.END)
            self.speed_result.insert(tk.END, result)
        threading.Thread(target=speed_test).start()

    def get_network_info(self):
        def network_info():
            info = f"System: {platform.system()} {platform.version()}\n"
            info += f"Machine: {platform.machine()}\n"
            info += f"Processor: {platform.processor()}\n"
            info += f"Hostname: {socket.gethostname()}\n"
            info += "Network Interfaces:\n"
            
            for interface, addrs in psutil.net_if_addrs().items():
                info += f"  {interface}:\n"
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        info += f"    IPv4 Address: {addr.address}\n"
                    elif addr.family == socket.AF_INET6:
                        info += f"    IPv6 Address: {addr.address}\n"
            
            self.info_result.delete(1.0, tk.END)
            self.info_result.insert(tk.END, info)
        threading.Thread(target=network_info).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetDiag(root)
    root.mainloop()