import tkinter as tk
from tkinter import ttk
from core.netInfoCore import infoExtractor

class NetInfoTab:
    def __init__(self, notebook, pcap_file):
        self.frame = tk.Frame(notebook)
        self.pcap_file = pcap_file
        self.notebook = notebook

        self.tree = ttk.Treeview(self.frame, columns=("Details",), show="tree")
        self.tree.column("#0", width=600, stretch=tk.YES)
        self.tree.pack(expand=True, fill="both")

        self.extract_and_display_info()

    def extract_and_display_info(self):
        data = infoExtractor(self.pcap_file)
        self.display_network_info(data)

    def display_network_info(self, data):
        self.tree.delete(*self.tree.get_children())
        count = 0

        for (src_ip, dst_ip, src_port, dst_port), d in data.items():
            label = f"{src_ip} ({d['OS'].get(src_ip, 'Unknown')}) : {src_port} → {dst_ip} ({d['OS'].get(dst_ip, 'Unknown')}) : {dst_port}"
            conv_id = self.tree.insert("", "end", text=label, open=False)
            count += 1

            def detail(label, items):
                return f"{label}: {', '.join(map(str, items)) if items else 'N/A'}"

            for key in ("MAC Addresses", "Ports", "Protocols"):
                self.tree.insert(conv_id, "end", text=detail(key, d.get(key)))

        self.frame.after(0, lambda: self.update_tab_title(count))

    def update_tab_title(self, count):
        i = self.notebook.index(self.frame)
        self.notebook.tab(i, text=f"Network Info ({count})")