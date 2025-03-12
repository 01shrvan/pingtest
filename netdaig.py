import subprocess
import socket
import platform
import psutil
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime
import json
import requests
import ipaddress

class NetDiag:
    def __init__(self, master):
        self.master = master
        master.title("NetDiag Pro - Network Diagnostic Tool")
        master.geometry("700x500")
        master.minsize(600, 400)
        
        # Set theme and style
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use a modern theme
        self.configure_styles()
        
        # Create main frame with padding
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(expand=True, fill="both")
        
        # Create header with app title and status
        self.create_header(main_frame)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill="both", pady=10)
        
        # Create all tabs
        self.create_ping_tab()
        self.create_dns_tab()
        self.create_speed_tab()
        self.create_traceroute_tab()
        self.create_port_scan_tab()
        self.create_info_tab()
        
        # Create footer with system info and progress bar
        self.create_footer(main_frame)
        
        # Initialize thread control flags
        self.ping_running = False
        self.scan_running = False
        
        # Show network info on startup
        self.master.after(500, self.get_network_info)

    def configure_styles(self):
        """Configure the styles for the UI elements"""
        self.style.configure('TButton', font=('Helvetica', 10))
        self.style.configure('TLabel', font=('Helvetica', 10))
        self.style.configure('TNotebook.Tab', padding=[10, 5], font=('Helvetica', 10))
        self.style.configure('Header.TLabel', font=('Helvetica', 16, 'bold'))
        self.style.configure('Status.TLabel', font=('Helvetica', 10, 'italic'))
        
    def create_header(self, parent):
        """Create the header with title and status"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill="x", pady=5)
        
        ttk.Label(header_frame, text="NetDiag Pro", style='Header.TLabel').pack(side="left")
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(header_frame, textvariable=self.status_var, style='Status.TLabel')
        self.status_label.pack(side="right")
        
    def create_footer(self, parent):
        """Create the footer with system info and progress bar"""
        footer_frame = ttk.Frame(parent)
        footer_frame.pack(fill="x", pady=5)
        
        system_info = f"System: {platform.system()} {platform.release()}"
        ttk.Label(footer_frame, text=system_info).pack(side="left")
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(footer_frame, variable=self.progress_var, 
                                        length=200, mode="determinate")
        self.progress.pack(side="right")
        
    def create_ping_tab(self):
        """Create the Ping Test tab"""
        ping_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(ping_frame, text="Ping Test")
        
        # Input frame
        input_frame = ttk.LabelFrame(ping_frame, text="Target", padding=5)
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ping_entry = ttk.Entry(input_frame, width=40)
        self.ping_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.ping_entry.insert(0, "google.com")
        
        # Options frame
        options_frame = ttk.LabelFrame(ping_frame, text="Options", padding=5)
        options_frame.pack(fill="x", pady=5)
        
        ttk.Label(options_frame, text="Count:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ping_count = ttk.Spinbox(options_frame, from_=1, to=100, width=5)
        self.ping_count.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.ping_count.insert(0, "4")
        
        self.continuous_ping = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Continuous", variable=self.continuous_ping).grid(
            row=0, column=2, padx=10, pady=5, sticky="w")
        
        # Button frame
        button_frame = ttk.Frame(ping_frame)
        button_frame.pack(fill="x", pady=5)
        
        self.ping_button = ttk.Button(button_frame, text="Run Ping Test", command=self.run_ping_test)
        self.ping_button.pack(side="left", padx=5)
        
        self.stop_ping_button = ttk.Button(button_frame, text="Stop", command=self.stop_ping_test, 
                                          state="disabled")
        self.stop_ping_button.pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.ping_result.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(ping_frame, text="Results")
        result_frame.pack(fill="both", expand=True, pady=5)
        
        self.ping_result = scrolledtext.ScrolledText(result_frame, width=80, height=15)
        self.ping_result.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_dns_tab(self):
        """Create the DNS Lookup tab"""
        dns_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(dns_frame, text="DNS Lookup")
        
        # Input frame
        input_frame = ttk.LabelFrame(dns_frame, text="Domain", padding=5)
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.dns_entry = ttk.Entry(input_frame, width=40)
        self.dns_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.dns_entry.insert(0, "python.org")
        
        # Record type frame
        record_frame = ttk.LabelFrame(dns_frame, text="Record Type", padding=5)
        record_frame.pack(fill="x", pady=5)
        
        self.record_type = ttk.Combobox(record_frame, 
                                       values=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "All"])
        self.record_type.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.record_type.current(0)
        
        # Button frame
        button_frame = ttk.Frame(dns_frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="Lookup DNS", command=self.run_dns_lookup).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.dns_result.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(dns_frame, text="Results")
        result_frame.pack(fill="both", expand=True, pady=5)
        
        self.dns_result = scrolledtext.ScrolledText(result_frame, width=80, height=15)
        self.dns_result.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_speed_tab(self):
        """Create the Speed Test tab"""
        speed_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(speed_frame, text="Speed Test")
        
        # Options frame
        options_frame = ttk.LabelFrame(speed_frame, text="Options", padding=5)
        options_frame.pack(fill="x", pady=5)
        
        ttk.Label(options_frame, text="Test Method:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.speed_method = ttk.Combobox(options_frame, 
                                        values=["HTTP Download/Upload", "ICMP Ping"])
        self.speed_method.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.speed_method.current(0)
        
        # Button frame
        button_frame = ttk.Frame(speed_frame)
        button_frame.pack(fill="x", pady=5)
        
        self.speed_button = ttk.Button(button_frame, text="Run Speed Test", command=self.run_speed_test)
        self.speed_button.pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.speed_result.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(speed_frame, text="Results")
        result_frame.pack(fill="both", expand=True, pady=5)
        
        self.speed_result = scrolledtext.ScrolledText(result_frame, width=80, height=15)
        self.speed_result.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_traceroute_tab(self):
        """Create the Traceroute tab"""
        traceroute_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(traceroute_frame, text="Traceroute")
        
        # Input frame
        input_frame = ttk.LabelFrame(traceroute_frame, text="Target", padding=5)
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.traceroute_entry = ttk.Entry(input_frame, width=40)
        self.traceroute_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.traceroute_entry.insert(0, "google.com")
        
        # Button frame
        button_frame = ttk.Frame(traceroute_frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="Run Traceroute", 
                  command=self.run_traceroute).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.traceroute_result.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(traceroute_frame, text="Results")
        result_frame.pack(fill="both", expand=True, pady=5)
        
        self.traceroute_result = scrolledtext.ScrolledText(result_frame, width=80, height=15)
        self.traceroute_result.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_port_scan_tab(self):
        """Create the Port Scan tab"""
        port_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(port_frame, text="Port Scan")
        
        # Input frame
        input_frame = ttk.LabelFrame(port_frame, text="Target", padding=5)
        input_frame.pack(fill="x", pady=5)
        
        ttk.Label(input_frame, text="Host:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ttk.Entry(input_frame, width=40)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.port_entry.insert(0, "localhost")
        
        # Port range frame
        range_frame = ttk.LabelFrame(port_frame, text="Port Range", padding=5)
        range_frame.pack(fill="x", pady=5)
        
        ttk.Label(range_frame, text="Start:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.port_start = ttk.Spinbox(range_frame, from_=1, to=65535, width=7)
        self.port_start.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.port_start.insert(0, "1")
        
        ttk.Label(range_frame, text="End:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.port_end = ttk.Spinbox(range_frame, from_=1, to=65535, width=7)
        self.port_end.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.port_end.insert(0, "1024")
        
        self.common_ports = tk.BooleanVar(value=True)
        ttk.Checkbutton(range_frame, text="Common Ports Only", 
                       variable=self.common_ports).grid(row=0, column=4, padx=10, pady=5, sticky="w")
        
        # Button frame
        button_frame = ttk.Frame(port_frame)
        button_frame.pack(fill="x", pady=5)
        
        self.scan_button = ttk.Button(button_frame, text="Scan Ports", command=self.run_port_scan)
        self.scan_button.pack(side="left", padx=5)
        
        self.stop_scan_button = ttk.Button(button_frame, text="Stop", 
                                          command=self.stop_port_scan, state="disabled")
        self.stop_scan_button.pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.port_result.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(port_frame, text="Results")
        result_frame.pack(fill="both", expand=True, pady=5)
        
        self.port_result = scrolledtext.ScrolledText(result_frame, width=80, height=15)
        self.port_result.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_info_tab(self):
        """Create the Network Info tab"""
        info_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(info_frame, text="Network Info")
        
        # Button frame
        button_frame = ttk.Frame(info_frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="Get Network Info", 
                  command=self.get_network_info).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Get Public IP", 
                  command=self.get_public_ip).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear", 
                  command=lambda: self.info_result.delete(1.0, tk.END)).pack(side="left", padx=5)
        
        # Results
        result_frame = ttk.LabelFrame(info_frame, text="System Information")
        result_frame.pack(fill="both", expand=True, pady=5)
        
        self.info_result = scrolledtext.ScrolledText(result_frame, width=80, height=15)
        self.info_result.pack(fill="both", expand=True, padx=5, pady=5)
        
    def run_ping_test(self):
        """Run a ping test to the specified host"""
        def ping():
            target = self.ping_entry.get().strip()
            if not target:
                self.show_error("Please enter a valid hostname or IP address")
                return
                
            try:
                count = int(self.ping_count.get())
                if count < 1:
                    raise ValueError("Count must be at least 1")
            except ValueError as e:
                self.show_error(f"Invalid count: {str(e)}")
                return
            
            self.ping_running = True
            self.ping_button.config(state="disabled")
            self.stop_ping_button.config(state="normal")
            
            if not self.continuous_ping.get():
                # Single ping test
                self.ping_result.delete(1.0, tk.END)
                self.update_status(f"Pinging {target}...")
                
                try:
                    # Use different commands based on OS
                    if platform.system().lower() == "windows":
                        command = ["ping", "-n", str(count), target]
                    else:
                        command = ["ping", "-c", str(count), target]
                    
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE, text=True)
                    
                    # Read output line by line
                    while True:
                        line = process.stdout.readline()
                        if not line and process.poll() is not None:
                            break
                        if line:
                            self.ping_result.insert(tk.END, line)
                            self.ping_result.see(tk.END)
                            self.master.update_idletasks()
                    
                    stderr = process.stderr.read()
                    if stderr:
                        self.ping_result.insert(tk.END, f"\nErrors:\n{stderr}")
                    
                    self.update_status("Ping completed")
                except Exception as e:
                    self.ping_result.insert(tk.END, f"Error: {str(e)}")
                    self.update_status("Ping failed")
            else:
                # Continuous ping
                self.ping_result.delete(1.0, tk.END)
                self.ping_result.insert(tk.END, f"Starting continuous ping to {target}...\n")
                self.update_status(f"Continuous ping to {target}...")
                
                ping_count = 0
                while self.ping_running:
                    ping_count += 1
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    try:
                        # Use different commands based on OS
                        if platform.system().lower() == "windows":
                            command = ["ping", "-n", "1", target]
                        else:
                            command = ["ping", "-c", "1", target]
                        
                        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                        output = result.stdout.strip()
                        
                        # Extract time from ping output
                        time_ms = "timeout"
                        if "time=" in output:
                            time_ms = output.split("time=")[1].split()[0]
                        elif "time<" in output:
                            time_ms = output.split("time<")[1].split()[0]
                        
                        self.ping_result.insert(tk.END, f"[{timestamp}] Ping {ping_count}: {time_ms}\n")
                        self.ping_result.see(tk.END)
                        
                        # Update progress bar for visual feedback
                        self.progress_var.set((ping_count % 10) * 10)
                        
                    except subprocess.TimeoutExpired:
                        self.ping_result.insert(tk.END, f"[{timestamp}] Ping {ping_count}: Timeout\n")
                        self.ping_result.see(tk.END)
                    except Exception as e:
                        self.ping_result.insert(tk.END, f"[{timestamp}] Error: {str(e)}\n")
                        self.ping_result.see(tk.END)
                    
                    # Sleep between pings
                    time.sleep(1)
            
            self.ping_button.config(state="normal")
            self.stop_ping_button.config(state="disabled")
            self.ping_running = False
            self.progress_var.set(0)
            
        threading.Thread(target=ping, daemon=True).start()
    
    def stop_ping_test(self):
        """Stop the continuous ping test"""
        self.ping_running = False
        self.update_status("Stopping ping...")
    
    def run_dns_lookup(self):
        """Perform a DNS lookup for the specified domain"""
        def dns_lookup():
            domain = self.dns_entry.get().strip()
            if not domain:
                self.show_error("Please enter a valid domain name")
                return
                
            record = self.record_type.get()
            
            self.dns_result.delete(1.0, tk.END)
            self.update_status(f"Looking up DNS for {domain}...")
            
            try:
                if record == "All":
                    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
                    self.dns_result.insert(tk.END, f"DNS lookup for {domain}:\n\n")
                    
                    for rec_type in record_types:
                        self.dns_result.insert(tk.END, f"--- {rec_type} Records ---\n")
                        try:
                            # Use nslookup for DNS lookup
                            if platform.system().lower() == "windows":
                                command = ["nslookup", "-type=" + rec_type, domain]
                            else:
                                command = ["nslookup", "-type=" + rec_type, domain]
                                
                            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                            self.dns_result.insert(tk.END, result.stdout)
                            
                        except Exception as e:
                            self.dns_result.insert(tk.END, f"Error: {str(e)}\n")
                        
                        self.dns_result.insert(tk.END, "\n")
                else:
                    self.dns_result.insert(tk.END, f"DNS lookup for {domain} ({record} records):\n\n")
                    try:
                        # Use nslookup for DNS lookup
                        if platform.system().lower() == "windows":
                            command = ["nslookup", "-type=" + record, domain]
                        else:
                            command = ["nslookup", "-type=" + record, domain]
                            
                        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                        self.dns_result.insert(tk.END, result.stdout)
                        
                    except Exception as e:
                        self.dns_result.insert(tk.END, f"Error: {str(e)}")
                
                self.update_status("DNS lookup completed")
            except Exception as e:
                self.dns_result.insert(tk.END, f"Error: {str(e)}")
                self.update_status("DNS lookup failed")
                
        threading.Thread(target=dns_lookup, daemon=True).start()
    
    def run_speed_test(self):
        """Run a network speed test"""
        def speed_test():
            self.speed_button.config(state="disabled")
            self.speed_result.delete(1.0, tk.END)
            self.speed_result.insert(tk.END, "Running speed test. This may take a minute...\n")
            self.update_status("Running speed test...")
            
            method = self.speed_method.get()
            
            try:
                if method == "HTTP Download/Upload":
                    self._http_speed_test()
                else:
                    self._icmp_speed_test()
            except Exception as e:
                self.speed_result.insert(tk.END, f"\nError: {str(e)}")
                self.update_status("Speed test failed")
            
            self.speed_button.config(state="normal")
            self.progress_var.set(0)
            
        threading.Thread(target=speed_test, daemon=True).start()
    
    def _http_speed_test(self):
        """Run a speed test using HTTP requests"""
        # Test download speed
        self.progress_var.set(10)
        self.speed_result.insert(tk.END, "Testing download speed...\n")
        
        # Use a large file from a CDN for download test
        download_url = "https://speed.cloudflare.com/__down?bytes=10000000"
        
        start_time = time.time()
        try:
            response = requests.get(download_url, stream=True, timeout=30)
            downloaded = 0
            
            self.progress_var.set(30)
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    downloaded += len(chunk)
            
            download_time = time.time() - start_time
            download_speed = (downloaded * 8) / download_time / 1_000_000  # Mbps
        except Exception as e:
            self.speed_result.insert(tk.END, f"Download test failed: {str(e)}\n")
            download_speed = 0
        
        # Test upload speed
        self.progress_var.set(50)
        self.speed_result.insert(tk.END, "Testing upload speed...\n")
        
        # Generate random data for upload
        data = b'0' * 1000000  # 1MB of data
        upload_url = "https://speed.cloudflare.com/__up"
        
        try:
            start_time = time.time()
            response = requests.post(upload_url, data=data, timeout=30)
            upload_time = time.time() - start_time
            upload_speed = (len(data) * 8) / upload_time / 1_000_000  # Mbps
        except Exception as e:
            self.speed_result.insert(tk.END, f"Upload test failed: {str(e)}\n")
            upload_speed = 0
        
        # Test latency
        self.progress_var.set(80)
        self.speed_result.insert(tk.END, "Testing latency...\n")
        
        ping_times = []
        try:
            for _ in range(5):
                start_time = time.time()
                requests.get("https://www.cloudflare.com/", timeout=5)
                ping_times.append((time.time() - start_time) * 1000)  # ms
            
            avg_ping = sum(ping_times) / len(ping_times)
        except Exception as e:
            self.speed_result.insert(tk.END, f"Latency test failed: {str(e)}\n")
            avg_ping = 0
        
        # Display results
        self.progress_var.set(100)
        self.speed_result.delete(1.0, tk.END)
        result = f"Speed Test Results (HTTP Method):\n\n"
        result += f"Download Speed: {download_speed:.2f} Mbps\n"
        result += f"Upload Speed: {upload_speed:.2f} Mbps\n"
        result += f"Ping: {avg_ping:.2f} ms\n\n"
        result += f"Test completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.speed_result.insert(tk.END, result)
        self.update_status("Speed test completed")
    
    def _icmp_speed_test(self):
        """Run a speed test using ICMP ping"""
        self.speed_result.insert(tk.END, "Testing latency to multiple servers...\n")
        
        servers = [
            "google.com",
            "cloudflare.com",
            "amazon.com",
            "microsoft.com",
            "apple.com"
        ]
        
        results = {}
        total_servers = len(servers)
        
        for i, server in enumerate(servers):
            self.progress_var.set((i / total_servers) * 100)
            self.speed_result.insert(tk.END, f"Pinging {server}...\n")
            self.master.update_idletasks()
            
            try:
                # Use ping command to measure latency
                if platform.system().lower() == "windows":
                    command = ["ping", "-n", "5", server]
                else:
                    command = ["ping", "-c", "5", server]
                
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                output = result.stdout
                
                # Parse ping results
                avg_time = 0
                if "Average" in output:  # Windows
                    avg_line = [line for line in output.split('\n') if "Average" in line][0]
                    avg_time = float(avg_line.split('=')[-1].strip().replace('ms', ''))
                elif "avg" in output:  # Unix
                    avg_line = [line for line in output.split('\n') if "avg" in line][0]
                    avg_time = float(avg_line.split('/')[-3])
                
                results[server] = avg_time
                
            except Exception as e:
                self.speed_result.insert(tk.END, f"Error pinging {server}: {str(e)}\n")
                results[server] = 0
        
        # Display results
        self.progress_var.set(100)
        self.speed_result.delete(1.0, tk.END)
        result = f"Speed Test Results (ICMP Method):\n\n"
        
        # Calculate average ping time
        valid_results = [v for v in results.values() if v > 0]
        avg_ping = sum(valid_results) / len(valid_results) if valid_results else 0
        
        result += f"Average Ping: {avg_ping:.2f} ms\n\n"
        result += "Individual Server Results:\n"
        
        for server, ping_time in results.items():
            result += f"{server}: {ping_time:.2f} ms\n"
        
        result += f"\nTest completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.speed_result.insert(tk.END, result)
        self.update_status("Speed test completed")
    
    def run_traceroute(self):
        """Run a traceroute to the specified host"""
        def traceroute():
            target = self.traceroute_entry.get().strip()
            if not target:
                self.show_error("Please enter a valid hostname or IP address")
                return
            
            self.traceroute_result.delete(1.0, tk.END)
            self.traceroute_result.insert(tk.END, f"Running traceroute to {target}...\n\n")
            self.update_status(f"Tracing route to {target}...")
            
            # Different command based on OS
            if platform.system().lower() == "windows":
                command = ["tracert", target]
            else:
                command = ["traceroute", target]
            
            try:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE, text=True)
                
                # Read output line by line
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        self.traceroute_result.insert(tk.END, line)
                        self.traceroute_result.see(tk.END)
                        self.master.update_idletasks()
                
                stderr = process.stderr.read()
                if stderr:
                    self.traceroute_result.insert(tk.END, f"\nErrors:\n{stderr}")
                
                self.update_status("Traceroute completed")
            except Exception as e:
                self.traceroute_result.insert(tk.END, f"Error: {str(e)}")
                self.update_status("Traceroute failed")
                
        threading.Thread(target=traceroute, daemon=True).start()
    
    def run_port_scan(self):
        """Scan ports on the specified host"""
        def port_scan():
            target = self.port_entry.get().strip()
            if not target:
                self.show_error("Please enter a valid hostname or IP address")
                return
            
            try:
                start_port = int(self.port_start.get())
                end_port = int(self.port_end.get())
                
                if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                    raise ValueError("Port numbers must be between 1 and 65535")
                
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
            except ValueError as e:
                self.show_error(f"Invalid port range: {str(e)}")
                return
            
            # Common ports dictionary
            common_ports = {
                20: "FTP Data",
                21: "FTP Control",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                465: "SMTPS",
                587: "SMTP Submission",
                993: "IMAPS",
                995: "POP3S",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                8080: "HTTP Alternate",
                8443: "HTTPS Alternate"
            }
            
            # If common ports only is selected, scan only those ports
            if self.common_ports.get():
                ports_to_scan = [p for p in common_ports.keys() if start_port <= p <= end_port]
            else:
                ports_to_scan = range(start_port, end_port + 1)
            
            self.scan_running = True
            self.scan_button.config(state="disabled")
            self.stop_scan_button.config(state="normal")
            
            self.port_result.delete(1.0, tk.END)
            self.port_result.insert(tk.END, f"Scanning {target} for open ports...\n\n")
            self.port_result.insert(tk.END, f"Port range: {start_port}-{end_port}\n")
            self.port_result.insert(tk.END, f"{'Common ports only' if self.common_ports.get() else 'All ports in range'}\n\n")
            self.port_result.insert(tk.END, "Port\tStatus\tService\n")
            self.port_result.insert(tk.END, "----\t------\t-------\n")
            
            self.update_status(f"Scanning ports on {target}...")
            
            open_ports = 0
            total_ports = len(ports_to_scan)
            
            # Use socket timeout for faster scanning
            socket.setdefaulttimeout(0.5)
            
            for i, port in enumerate(ports_to_scan):
                if not self.scan_running:
                    self.port_result.insert(tk.END, "\nScan stopped by user")
                    break
                
                # Update progress
                progress = (i / total_ports) * 100
                self.progress_var.set(progress)
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = common_ports.get(port, "Unknown")
                        self.port_result.insert(tk.END, f"{port}\tOpen\t{service}\n")
                        open_ports += 1
                    sock.close()
                except Exception:
                    pass
                
                # Update the UI occasionally
                if i % 10 == 0 or i == total_ports - 1:
                    self.port_result.see(tk.END)
                    self.master.update_idletasks()
            
            self.port_result.insert(tk.END, f"\nScan completed. Found {open_ports} open port(s).")
            self.update_status("Port scan completed")
            
            self.scan_button.config(state="normal")
            self.stop_scan_button.config(state="disabled")
            self.scan_running = False
            self.progress_var.set(0)
            
        threading.Thread(target=port_scan, daemon=True).start()
    
    def stop_port_scan(self):
        """Stop the port scan"""
        self.scan_running = False
        self.update_status("Stopping port scan...")
    
    def get_network_info(self):
        """Get information about the system's network interfaces"""
        def network_info():
            self.info_result.delete(1.0, tk.END)
            self.update_status("Gathering network information...")
            
            info = f"System Information:\n"
            info += f"===================\n\n"
            info += f"System: {platform.system()} {platform.version()}\n"
            info += f"Machine: {platform.machine()}\n"
            info += f"Processor: {platform.processor()}\n"
            info += f"Hostname: {socket.gethostname()}\n"
            info += f"Python Version: {platform.python_version()}\n\n"
            
            info += f"Network Interfaces:\n"
            info += f"===================\n\n"
            
            for interface, addrs in psutil.net_if_addrs().items():
                info += f"  {interface}:\n"
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        info += f"    IPv4 Address: {addr.address}\n"
                        info += f"    Netmask: {addr.netmask}\n"
                    elif addr.family == socket.AF_INET6:
                        info += f"    IPv6 Address: {addr.address}\n"
                info += "\n"
            
            # Get network stats
            info += f"Network Statistics:\n"
            info += f"===================\n\n"
            
            net_io = psutil.net_io_counters()
            info += f"Bytes Sent: {self.format_bytes(net_io.bytes_sent)}\n"
            info += f"Bytes Received: {self.format_bytes(net_io.bytes_recv)}\n"
            info += f"Packets Sent: {net_io.packets_sent}\n"
            info += f"Packets Received: {net_io.packets_recv}\n\n"
            
            # Get active connections
            info += f"Active Connections:\n"
            info += f"===================\n\n"
            
            try:
                connections = psutil.net_connections()
                for conn in connections[:20]:  # Limit to first 20 connections
                    if conn.status == 'ESTABLISHED':
                        try:
                            local = f"{conn.laddr.ip}:{conn.laddr.port}"
                            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                            info += f"  {local} -> {remote} ({conn.status})\n"
                        except:
                            pass
                
                if len(connections) > 20:
                    info += f"\n  ... and {len(connections) - 20} more connections\n"
            except:
                info += "  Could not retrieve connection information (requires admin privileges)\n"
            
            self.info_result.delete(1.0, tk.END)
            self.info_result.insert(tk.END, info)
            self.update_status("Network information gathered")
            
        threading.Thread(target=network_info, daemon=True).start()
    
    def get_public_ip(self):
        """Get the public IP address and related information"""
        def fetch_ip():
            self.update_status("Fetching public IP address...")
            
            try:
                # Try multiple IP services in case one fails
                try:
                    response = requests.get("https://api.ipify.org?format=json", timeout=5)
                    data = response.json()
                    ip = data["ip"]
                except:
                    try:
                        response = requests.get("https://ifconfig.me/ip", timeout=5)
                        ip = response.text.strip()
                    except:
                        response = requests.get("https://icanhazip.com", timeout=5)
                        ip = response.text.strip()
                
                # Get additional IP information
                try:
                    geo_response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
                    geo_data = geo_response.json()
                except:
                    geo_data = {}
                
                info = f"Public IP Information:\n"
                info += f"=====================\n\n"
                info += f"IP Address: {ip}\n"
                
                if "country_name" in geo_data:
                    info += f"Country: {geo_data.get('country_name', 'Unknown')}\n"
                    info += f"Region: {geo_data.get('region', 'Unknown')}\n"
                    info += f"City: {geo_data.get('city', 'Unknown')}\n"
                    info += f"ISP: {geo_data.get('org', 'Unknown')}\n"
                    info += f"Timezone: {geo_data.get('timezone', 'Unknown')}\n"
                
                # Try to determine if IP is in a private range
                try:
                    is_private = ipaddress.ip_address(ip).is_private
                    info += f"Private IP: {'Yes' if is_private else 'No'}\n"
                except:
                    pass
                
                self.info_result.delete(1.0, tk.END)
                self.info_result.insert(tk.END, info)
                self.update_status("Public IP information retrieved")
            except Exception as e:
                self.info_result.delete(1.0, tk.END)
                self.info_result.insert(tk.END, f"Error fetching public IP: {str(e)}")
                self.update_status("Failed to retrieve public IP")
                
        threading.Thread(target=fetch_ip, daemon=True).start()
    
    def update_status(self, message):
        """Update the status message in the UI"""
        self.status_var.set(message)
        self.master.update_idletasks()
    
    def show_error(self, message):
        """Show an error message dialog"""
        messagebox.showerror("Error", message)
    
    def format_bytes(self, bytes):
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"

if __name__ == "__main__":
    root = tk.Tk()
    app = NetDiag(root)
    root.mainloop()