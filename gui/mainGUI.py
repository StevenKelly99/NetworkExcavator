import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, PhotoImage
from gui.imagesGUI import ImagesTab
from gui.netInfoGUI import NetInfoTab
from gui.filesGUI import FileInfoTab

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def resource_path(relative_path):
    """Get absolute path to resource (dev and PyInstaller/py2app compatible)."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class MainGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetworkExcavator")
        self.root.geometry("900x600")

        self.pcap_file = None
        self.images_tab = None
        self.current_tabs = []

        self.build_ui()

    def build_ui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill="x", padx=10, pady=10)
        tk.Button(top_frame, text="Upload PCAP", command=self.select_pcap_file).pack(anchor="center")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both")
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        self.add_welcome_tab()

    def add_welcome_tab(self):
        self.welcome_tab = tk.Frame(self.notebook)
        self.notebook.add(self.welcome_tab, text="Welcome")

        image_path = resource_path("images/logo.png")
        self.welcome_image = PhotoImage(file=image_path)

        inner = tk.Frame(self.welcome_tab)
        inner.place(relx=0.5, rely=0.4, anchor="center")

        tk.Label(
            inner,
            text="👋 Welcome to NetworkExcavator!\nPlease don't be shy — choose a PCAP to get started.",
            font=("Helvetica", 14),
            justify="center"
        ).pack(pady=(0, 15))

        tk.Label(inner, image=self.welcome_image).pack()

    def select_pcap_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            self.pcap_file = file_path
            self.load_tabs()

    def clear_tabs(self):
        for tab in self.current_tabs:
            self.notebook.forget(tab)
        self.current_tabs.clear()
        self.images_tab = None

    def load_tabs(self):
        self.clear_tabs()
        if self.welcome_tab:
            self.notebook.forget(self.welcome_tab)
            self.welcome_tab = None

        self.add_tab(NetInfoTab, "Network Info (Loading...)")
        self.add_tab(ImagesTab, "Images (Loading...)", is_images_tab=True)
        self.add_tab(FileInfoTab, "File Transfers (Loading...)")

    def add_tab(self, tab_class, title, is_images_tab=False):
        tab = tab_class(self.notebook, self.pcap_file)
        self.notebook.add(tab.frame, text=title)
        self.current_tabs.append(tab.frame)

        if is_images_tab:
            self.images_tab = tab
            self.root.after(1000, lambda: self.update_images_tab_title(tab))

    def update_images_tab_title(self, tab):
        try:
            count = tab.get_image_count()
            idx = self.notebook.index(tab.frame)
            self.notebook.tab(idx, text=f"Images ({count})")
        except tk.TclError:
            print("Error: ImagesTab frame not registered.")

    def on_tab_change(self, event):
        selected = event.widget.select()
        if self.images_tab and selected == self.images_tab.frame:
            self.images_tab.refresh()

def run_gui():
    if getattr(sys, 'frozen', False):
        os.chdir(sys._MEIPASS)

    root = tk.Tk()
    window_width = 900
    window_height = 600
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = int((screen_width / 2) - (window_width / 2))
    y = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    app = MainGUI(root)
    root.mainloop()