import os, sys, queue, subprocess, time
import tkinter as tk
from PIL import Image, ImageTk, UnidentifiedImageError
from threading import Thread

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.imagesCore import extractImages

EXTRACTED_IMAGES_DIR = "artifacts/images"


class ImagesTab:
    def __init__(self, notebook, pcap_file):
        self.frame = tk.Frame(notebook)
        self.notebook, self.pcap_file = notebook, pcap_file
        self.image_cache, self.queue, self.image_count = [], queue.Queue(), 0

        self.canvas = tk.Canvas(self.frame)
        self.scrollbar_x = tk.Scrollbar(self.frame, orient="horizontal", command=self.canvas.xview)
        self.scrollbar_y = tk.Scrollbar(self.frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")
        ))

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(xscrollcommand=self.scrollbar_x.set, yscrollcommand=self.scrollbar_y.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar_y.grid(row=0, column=1, sticky="ns")
        self.scrollbar_x.grid(row=1, column=0, sticky="ew")

        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)

        Thread(target=self.process_images, daemon=True).start()
        self.frame.after(200, self.check_queue)

    def process_images(self):
        if os.path.exists(EXTRACTED_IMAGES_DIR):
            for f in os.listdir(EXTRACTED_IMAGES_DIR):
                try:
                    os.remove(os.path.join(EXTRACTED_IMAGES_DIR, f))
                except:
                    pass
        else:
            os.makedirs(EXTRACTED_IMAGES_DIR, exist_ok=True)

        extractImages(self.pcap_file)
        time.sleep(0.5)
        self.queue.put(self.display_images)

    def display_images(self):
        for w in self.scrollable_frame.winfo_children():
            w.destroy()

        files = sorted(os.listdir(EXTRACTED_IMAGES_DIR)) if os.path.exists(EXTRACTED_IMAGES_DIR) else []
        images = []

        for f in files:
            path = os.path.join(EXTRACTED_IMAGES_DIR, f)
            if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico')):
                if os.path.isfile(path):
                    images.append(path)

        self.image_cache.clear()
        self.image_count = len(images)
        self.update_tab_title()

        for idx, path in enumerate(images):
            Thread(target=self.load_image, args=(path, idx), daemon=True).start()

    def load_image(self, path, index):
        try:
            with Image.open(path) as im:
                im.verify()
            with Image.open(path) as im:
                img = im.convert("RGB")
                if img.width < 64 or img.height < 64:
                    img = img.resize((100, 100), Image.LANCZOS)
                else:
                    img.thumbnail((100, 100), Image.LANCZOS)
                img_tk = ImageTk.PhotoImage(img)
        except (UnidentifiedImageError, OSError):
            img = Image.new("RGB", (100, 100), color="red")
            img_tk = ImageTk.PhotoImage(img)

        self.queue.put(lambda: self.add_image(img_tk, path, index))

    def add_image(self, img_tk, path, index):
        row, col = divmod(index, 6)
        frame = tk.Frame(self.scrollable_frame, padx=10, pady=10)
        frame.grid(row=row, column=col)

        img_label = tk.Label(frame, image=img_tk, cursor="hand2")
        img_label.image = img_tk
        img_label.pack()
        img_label.bind("<Double-Button-1>", lambda e: self.open_image(path))

        name_label = tk.Label(frame, text=os.path.basename(path), cursor="hand2")
        name_label.pack()
        name_label.bind("<Double-Button-1>", lambda e: self.open_image(path))

        self.image_cache.append(img_tk)

    def open_image(self, path):
        try:
            if sys.platform.startswith("darwin"):
                subprocess.run(["open", path])
            elif sys.platform.startswith("win"):
                os.startfile(path)
            else:
                subprocess.run(["xdg-open", path])
        except:
            pass

    def check_queue(self):
        while not self.queue.empty():
            try:
                self.queue.get()()
            except:
                pass
        self.frame.after(200, self.check_queue)

    def update_tab_title(self):
        try:
            i = self.notebook.index(self.frame)
            self.notebook.tab(i, text=f"Images ({self.image_count})")
        except:
            pass

    def get_image_count(self):
        return self.image_count

    def refresh(self):
        Thread(target=self.process_images, daemon=True).start()
