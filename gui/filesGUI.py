import tkinter as tk
from tkinter import ttk
from core.filesCore import parsePcapForFiles

class FileInfoTab:
    def __init__(self, notebook, pcap_file):
        self.notebook = notebook
        self.frame = tk.Frame(notebook)
        self.pcap_file = pcap_file

        cols = ("No.", "Source IP", "Destination IP", "File Name")
        self.tree = ttk.Treeview(self.frame, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", stretch=True)

        self.tree.pack(expand=True, fill="both")
        self.frame.after(100, self.load_and_display)

    def load_and_display(self):
        try:
            data = parsePcapForFiles(self.pcap_file)
            self.tree.delete(*self.tree.get_children())
            for idx, row in enumerate(data, start=1):
                numbered_row = (idx,) + tuple(row)
                self.tree.insert("", "end", values=numbered_row)
            self.update_tab_title()
        except Exception as e:
            print("Failed to load file info tab:", e)

    def update_tab_title(self):
        try:
            idx = self.notebook.index(self.frame)
            count = len(self.tree.get_children())
            self.notebook.tab(idx, text=f"File Transfers ({count})")
        except Exception as e:
            print("Failed to update File Transfers tab title:", e)
