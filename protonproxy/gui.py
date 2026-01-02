"""Tkinter GUI for ProtonVPN proxy."""

import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser
import requests
from typing import Optional, List

from .api import api, ProtonAPIError
from .auth import get_login_url, generate_state, parse_selector_input, consume_fork, check_login, logout
from .servers import get_servers, get_countries, Logical, get_server_by_name
from .proxy import LocalProxy, UpstreamProxy, set_upstream_proxy
from .credentials import clear_credentials

class LogRedirector:
    """Redirect stdout/stderr to a tkinter text widget."""
    def __init__(self, text_widget: scrolledtext.ScrolledText):
        self.text_widget = text_widget

    def write(self, str):
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, str)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state='disabled')

    def flush(self):
        pass

class ProtonProxyGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ProtonProxy GUI")
        self.root.geometry("800x600")
        
        self.proxy: Optional[LocalProxy] = None
        self.proxy_thread: Optional[threading.Thread] = None
        self.servers: List[Logical] = []
        
        self._setup_ui()
        self._update_status()
        
        # Redirect stdout to logs
        sys.stdout = LogRedirector(self.log_area)
        sys.stderr = LogRedirector(self.log_area)

    def _set_icon(self):
        """Set application icon."""
        import os
        try:
            # Load icon from the package directory
            icon_path = os.path.join(os.path.dirname(__file__), "com.protonvpn.www.png")
            img = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, img)
        except Exception as e:
            print(f"Failed to set icon: {e}")

    def _setup_ui(self):
        self._set_icon()
        # Main layout
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Status and Auth Frame
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication", padding="10")
        auth_frame.pack(fill=tk.X, pady=5)

        self.status_var = tk.StringVar(value="Checking status...")
        ttk.Label(auth_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)

        self.login_btn = ttk.Button(auth_frame, text="Login", command=self._handle_login)
        self.login_btn.pack(side=tk.RIGHT, padx=5)

        self.logout_btn = ttk.Button(auth_frame, text="Logout", command=self._handle_logout)
        self.logout_btn.pack(side=tk.RIGHT, padx=5)

        # Proxy Config Frame
        config_frame = ttk.LabelFrame(main_frame, text="Proxy Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=5)

        ttk.Label(config_frame, text="Host:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.host_entry = ttk.Entry(config_frame)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)

        ttk.Label(config_frame, text="Port:").grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)
        self.port_entry = ttk.Entry(config_frame)
        self.port_entry.insert(0, "8080")
        self.port_entry.grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)

        ttk.Label(config_frame, text="Upstream:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.upstream_entry = ttk.Entry(config_frame, width=40)
        self.upstream_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=2, sticky=tk.W)

        # Server Selection Frame
        server_frame = ttk.LabelFrame(main_frame, text="Server Selection", padding="10")
        server_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        filter_frame = ttk.Frame(server_frame)
        filter_frame.pack(fill=tk.X, pady=2)

        ttk.Label(filter_frame, text="Country:").pack(side=tk.LEFT)
        self.country_cb = ttk.Combobox(filter_frame, state="readonly")
        self.country_cb.pack(side=tk.LEFT, padx=5)
        self.country_cb.bind("<<ComboboxSelected>>", self._on_country_selected)

        self.all_tiers_var = tk.BooleanVar(value=False)
        self.all_tiers_chk = ttk.Checkbutton(filter_frame, text="Show All Tiers", variable=self.all_tiers_var, command=self._refresh_servers)
        self.all_tiers_chk.pack(side=tk.LEFT, padx=10)

        self.refresh_btn = ttk.Button(filter_frame, text="Refresh", command=self._refresh_servers)
        self.refresh_btn.pack(side=tk.RIGHT)

        # Server Treeview
        columns = ("name", "country", "city", "tier", "load")
        self.server_tree = ttk.Treeview(server_frame, columns=columns, show="headings")
        self.server_tree.heading("name", text="Name")
        self.server_tree.heading("country", text="Country")
        self.server_tree.heading("city", text="City")
        self.server_tree.heading("tier", text="Tier")
        self.server_tree.heading("load", text="Load")
        
        self.server_tree.column("name", width=150)
        self.server_tree.column("country", width=100)
        self.server_tree.column("city", width=150)
        self.server_tree.column("tier", width=80)
        self.server_tree.column("load", width=80)
        
        self.server_tree.pack(fill=tk.BOTH, expand=True, pady=5)

        # Control Frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)

        self.start_btn = ttk.Button(control_frame, text="Start Proxy", command=self._handle_start)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop Proxy", command=self._handle_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.check_btn = ttk.Button(control_frame, text="Check Connection", command=self._handle_check_connection)
        self.check_btn.pack(side=tk.LEFT, padx=5)

        # Log Area
        log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Monaco", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def _update_status(self):
        if check_login():
            self.status_var.set("Status: Logged In")
            self.login_btn.configure(state=tk.DISABLED)
            self.logout_btn.configure(state=tk.NORMAL)
            self._refresh_countries()
        else:
            self.status_var.set("Status: Not Logged In")
            self.login_btn.configure(state=tk.NORMAL)
            self.logout_btn.configure(state=tk.DISABLED)

    def _handle_login(self):
        state = generate_state()
        login_url = get_login_url(state)
        webbrowser.open(login_url)
        
        selector_window = tk.Toplevel(self.root)
        selector_window.title("Enter Selector")
        selector_window.geometry("400x150")
        
        ttk.Label(selector_window, text="Please paste the Selector from the browser:").pack(pady=10)
        entry = ttk.Entry(selector_window, width=50)
        entry.pack(pady=5)
        entry.focus_set()

        def submit():
            user_input = entry.get().strip()
            if not user_input:
                return
            
            try:
                selector = parse_selector_input(user_input)
                result = consume_fork(selector)
                api.set_session(
                    result["UID"],
                    result["AccessToken"],
                    result["RefreshToken"],
                )
                messagebox.showinfo("Success", "Login successful!")
                selector_window.destroy()
                self._update_status()
            except Exception as e:
                messagebox.showerror("Error", f"Login failed: {e}")

        ttk.Button(selector_window, text="Submit", command=submit).pack(pady=10)

    def _handle_logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            logout()
            clear_credentials()
            self._update_status()
            self.server_tree.delete(*self.server_tree.get_children())
            self.country_cb.set("")
            self.country_cb['values'] = []

    def _refresh_countries(self):
        try:
            countries = get_countries(free_only=not self.all_tiers_var.get())
            self.country_cb['values'] = ["All"] + countries
            if not self.country_cb.get():
                self.country_cb.set("All")
            self._refresh_servers()
        except Exception as e:
            print(f"Error fetching countries: {e}")

    def _on_country_selected(self, event):
        self._refresh_servers()

    def _refresh_servers(self):
        if not check_login():
            return
            
        try:
            country = self.country_cb.get()
            if country == "All":
                country = None
                
            self.servers = get_servers(
                country=country,
                free_only=not self.all_tiers_var.get()
            )
            
            self.server_tree.delete(*self.server_tree.get_children())
            for s in self.servers:
                tier = "Free" if s.is_free() else "Plus"
                load = f"{s.load}%" if s.load is not None else "-"
                self.server_tree.insert("", tk.END, values=(s.name, s.exit_country, s.city or "-", tier, load))
        except Exception as e:
            print(f"Error fetching servers: {e}")

    def _handle_start(self):
        selected = self.server_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a server first.")
            return
        
        server_name = self.server_tree.item(selected[0])['values'][0]
        server = get_server_by_name(server_name)
        
        if not server:
            messagebox.showerror("Error", f"Server {server_name} not found.")
            return

        host = self.host_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return

        upstream_url = self.upstream_entry.get().strip()
        if upstream_url:
            try:
                upstream = UpstreamProxy.from_url(upstream_url)
                set_upstream_proxy(upstream)
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid upstream proxy: {e}")
                return
        else:
            set_upstream_proxy(None)

        self.proxy = LocalProxy(host=host, port=port)
        self.proxy_thread = threading.Thread(target=self.proxy.start, args=(server,), daemon=True)
        self.proxy_thread.start()
        
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.host_entry.configure(state=tk.DISABLED)
        self.port_entry.configure(state=tk.DISABLED)
        self.upstream_entry.configure(state=tk.DISABLED)

    def _handle_stop(self):
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
            
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.host_entry.configure(state=tk.NORMAL)
        self.port_entry.configure(state=tk.NORMAL)
        self.upstream_entry.configure(state=tk.NORMAL)

    def _handle_check_connection(self):
        """Check if proxy connection is working."""
        if not self.proxy or not self.proxy.running:
            messagebox.showwarning("Warning", "Proxy is not running. Please start the proxy first.")
            return

        self.check_btn.configure(state=tk.DISABLED)
        self.status_var.set("Status: Checking connection...")
        
        thread = threading.Thread(target=self._run_check, daemon=True)
        thread.start()

    def _run_check(self):
        host = self.host_entry.get()
        port = self.port_entry.get()
        proxies = {
            "http": f"http://{host}:{port}",
            "https": f"http://{host}:{port}",
        }
        
        try:
            # First check without proxy to get real IP (optional, but good for comparison? No, just check proxy)
            # Just check if we can reach an IP echo service via proxy
            response = requests.get("http://ip-api.com/json", proxies=proxies, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            result_msg = (
                f"Connection Successful!\n\n"
                f"IP: {data.get('query')}\n"
                f"Country: {data.get('country')}\n"
                f"ISP: {data.get('isp')}"
            )
            
            self.root.after(0, lambda: messagebox.showinfo("Success", result_msg))
            self.root.after(0, lambda: self.status_var.set("Status: Connected"))
            
        except Exception as e:
            error_msg = f"Connection check failed:\n{str(e)}"
            self.root.after(0, lambda: messagebox.showerror("Error", error_msg))
            self.root.after(0, lambda: self.status_var.set("Status: Connection Failed"))
        finally:
             self.root.after(0, lambda: self.check_btn.configure(state=tk.NORMAL))

def main():
    root = tk.Tk()
    # Handle window close
    def on_closing():
        # Stop proxy if running
        # sys.exit will handle thread termination if daemon=True
        root.destroy()
        sys.exit(0)
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    app = ProtonProxyGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
