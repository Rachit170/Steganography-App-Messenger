import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
from steganography_core import (
    embed_message_in_image,
    extract_message_from_image,
    encrypt_message,
    decrypt_message,
    get_fernet_key,
    DELIMITER
)
from cryptography.fernet import InvalidToken
from tkinterdnd2 import DND_FILES, TkinterDnD
import ttkbootstrap as tb
from ttkbootstrap.constants import *

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secret Image Messenger")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        
        self.style = tb.Style(theme="minty")
        
        
        self.primary_color = "#5cb85c"
        self.secondary_color = "#5bc0de"
        self.accent_color = "#f0ad4e"
        
        
        self.use_encryption = tk.BooleanVar(value=False)
        self.encryption_password = tk.StringVar()
        self.use_encryption_extract = tk.BooleanVar(value=False)
        self.encryption_password_extract = tk.StringVar()

        self.setup_ui()

        
        self.cover_image = None
        self.stego_image = None

        
        self.cover_image_path = None
        self.stego_image_path = None

    def setup_ui(self):
        
        main_frame = tb.Frame(self.root, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)
        
       
        header_frame = tb.Frame(main_frame)
        header_frame.pack(fill=X, pady=(0, 20))
        
        
        icon_label = tb.Label(
            header_frame, 
            text="🔐", 
            font=("Arial", 24),
            bootstyle=SECONDARY
        )
        icon_label.pack(side=LEFT, padx=(0, 10))
        
        title_label = tb.Label(
            header_frame,
            text="Secret Image Messenger",
            font=("Arial", 20, "bold"),
            bootstyle=PRIMARY
        )
        title_label.pack(side=LEFT)
        
        subtitle_label = tb.Label(
            main_frame,
            text="Hide and reveal secret messages in images",
            font=("Arial", 10),
            bootstyle=SECONDARY
        )
        subtitle_label.pack(fill=X, pady=(0, 20))
        
        
        self.notebook = tb.Notebook(main_frame, bootstyle=PRIMARY)
        self.notebook.pack(fill=BOTH, expand=YES)
        
        
        embed_tab = tb.Frame(self.notebook, padding=15)
        self.notebook.add(embed_tab, text="Hide Message")
        
        
        extract_tab = tb.Frame(self.notebook, padding=15)
        self.notebook.add(extract_tab, text="Reveal Message")
        
        
        self.setup_embed_tab(embed_tab)
        self.setup_extract_tab(extract_tab)
        
        
        self.status_var = tk.StringVar(value="Ready to hide or reveal secrets!")
        status_bar = tb.Label(
            main_frame,
            textvariable=self.status_var,
            relief=FLAT,
            anchor=CENTER,
            font=("Arial", 9),
            bootstyle=(SECONDARY, INVERSE)
        )
        status_bar.pack(fill=X, pady=(10, 0))
        
        
        for i in range(2):
            self.notebook.columnconfigure(i, weight=1)
            self.notebook.rowconfigure(i, weight=1)

    def setup_embed_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        
        
        cover_frame = tb.LabelFrame(
            parent, 
            text=" Select Cover Image ", 
            padding=15,
            bootstyle=INFO
        )
        cover_frame.grid(row=0, column=0, sticky=EW, pady=(0, 15))
        cover_frame.columnconfigure(1, weight=1)
        
        tb.Label(
            cover_frame, 
            text="Image:", 
            font=("Arial", 10, "bold"),
            bootstyle=INFO
        ).grid(row=0, column=0, sticky=W, padx=(0, 10))
        
        self.cover_image_label = tb.Label(
            cover_frame, 
            text="No image selected", 
            foreground="gray",
            font=("Arial", 10),
            anchor=W
        )
        self.cover_image_label.grid(row=0, column=1, sticky=EW)
        
        browse_btn = tb.Button(
            cover_frame,
            text="Browse",
            command=self.select_cover_image,
            bootstyle=(OUTLINE, INFO),
            width=10
        )
        browse_btn.grid(row=0, column=2, padx=(10, 0))
        
        
        preview_frame = tb.Frame(cover_frame)
        preview_frame.grid(row=1, column=0, columnspan=3, pady=(10, 0))
        
        self.cover_image_preview = tb.Label(preview_frame)
        self.cover_image_preview.pack()
        
        
        message_frame = tb.LabelFrame(
            parent, 
            text=" Secret Message ", 
            padding=15,
            bootstyle=SUCCESS
        )
        message_frame.grid(row=1, column=0, sticky=NSEW, pady=(0, 15))
        message_frame.columnconfigure(0, weight=1)
        
        self.message_text = scrolledtext.ScrolledText(
            message_frame, 
            height=8,
            wrap=WORD,
            font=("Arial", 10),
            padx=10,
            pady=10
        )
        self.message_text.pack(fill=BOTH, expand=YES)
        
        
        encrypt_frame = tb.Frame(parent)
        encrypt_frame.grid(row=2, column=0, sticky=EW, pady=(0, 15))
        
        self.encrypt_check = tb.Checkbutton(
            encrypt_frame,
            text="Encrypt Message",
            variable=self.use_encryption,
            command=self.toggle_password_entry,
            bootstyle=SUCCESS,
            onvalue=True,
            offvalue=False
        )
        self.encrypt_check.pack(side=LEFT, padx=(0, 10))
        
        self.password_label = tb.Label(
            encrypt_frame, 
            text="Password:",
            bootstyle=SUCCESS
        )
        self.password_entry = tb.Entry(
            encrypt_frame,
            textvariable=self.encryption_password,
            show="*",
            width=20,
            bootstyle=SUCCESS
        )
        self.password_label.pack(side=LEFT, padx=(0, 5))
        self.password_entry.pack(side=LEFT)
        self.password_label.pack_forget()
        self.password_entry.pack_forget()
        
        
        self.embed_button = tb.Button(
            parent,
            text="Hide Message in Image",
            command=self.embed_message,
            state=DISABLED,
            bootstyle=(SUCCESS, OUTLINE),
            width=20
        )
        self.embed_button.grid(row=3, column=0, pady=(10, 0))
        
        
        self.cover_image_label.drop_target_register(DND_FILES)
        self.cover_image_label.dnd_bind('<<Drop>>', self.on_cover_image_drop)

    def setup_extract_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        
        
        stego_frame = tb.LabelFrame(
            parent, 
            text=" Select Image with Hidden Message ", 
            padding=15,
            bootstyle=WARNING
        )
        stego_frame.grid(row=0, column=0, sticky=EW, pady=(0, 15))
        stego_frame.columnconfigure(1, weight=1)
        
        tb.Label(
            stego_frame, 
            text="Image:", 
            font=("Arial", 10, "bold"),
            bootstyle=WARNING
        ).grid(row=0, column=0, sticky=W, padx=(0, 10))
        
        self.stego_image_label = tb.Label(
            stego_frame, 
            text="No image selected", 
            foreground="gray",
            font=("Arial", 10),
            anchor=W
        )
        self.stego_image_label.grid(row=0, column=1, sticky=EW)
        
        browse_btn = tb.Button(
            stego_frame,
            text="Browse",
            command=self.select_stego_image,
            bootstyle=(OUTLINE, WARNING),
            width=10
        )
        browse_btn.grid(row=0, column=2, padx=(10, 0))
        
        
        preview_frame = tb.Frame(stego_frame)
        preview_frame.grid(row=1, column=0, columnspan=3, pady=(10, 0))
        
        self.stego_image_preview = tb.Label(preview_frame)
        self.stego_image_preview.pack()
        
        
        decrypt_frame = tb.Frame(parent)
        decrypt_frame.grid(row=1, column=0, sticky=EW, pady=(0, 15))
        
        self.decrypt_check = tb.Checkbutton(
            decrypt_frame,
            text="Decrypt Message",
            variable=self.use_encryption_extract,
            command=self.toggle_password_entry_extract,
            bootstyle=WARNING,
            onvalue=True,
            offvalue=False
        )
        self.decrypt_check.pack(side=LEFT, padx=(0, 10))
        
        self.password_label_extract = tb.Label(
            decrypt_frame, 
            text="Password:",
            bootstyle=WARNING
        )
        self.password_entry_extract = tb.Entry(
            decrypt_frame,
            textvariable=self.encryption_password_extract,
            show="*",
            width=20,
            bootstyle=WARNING
        )
        self.password_label_extract.pack(side=LEFT, padx=(0, 5))
        self.password_entry_extract.pack(side=LEFT)
        self.password_label_extract.pack_forget()
        self.password_entry_extract.pack_forget()
        
        
        extracted_frame = tb.LabelFrame(
            parent, 
            text=" Revealed Message ", 
            padding=15,
            bootstyle=PRIMARY
        )
        extracted_frame.grid(row=2, column=0, sticky=NSEW, pady=(0, 15))
        extracted_frame.columnconfigure(0, weight=1)
        
        self.extracted_text = scrolledtext.ScrolledText(
            extracted_frame, 
            height=8,
            wrap=WORD,
            font=("Arial", 10),
            padx=10,
            pady=10,
            state=DISABLED
        )
        self.extracted_text.pack(fill=BOTH, expand=YES)
        
        
        self.extract_button = tb.Button(
            parent,
            text="Reveal Hidden Message",
            command=self.extract_message,
            state=DISABLED,
            bootstyle=(PRIMARY, OUTLINE),
            width=20
        )
        self.extract_button.grid(row=3, column=0, pady=(10, 0))
        
        
        self.stego_image_label.drop_target_register(DND_FILES)
        self.stego_image_label.dnd_bind('<<Drop>>', self.on_stego_image_drop)

    def toggle_password_entry(self):
        if self.use_encryption.get():
            self.password_label.pack(side=LEFT, padx=(0, 5))
            self.password_entry.pack(side=LEFT)
        else:
            self.password_label.pack_forget()
            self.password_entry.pack_forget()

    def toggle_password_entry_extract(self):
        if self.use_encryption_extract.get():
            self.password_label_extract.pack(side=LEFT, padx=(0, 5))
            self.password_entry_extract.pack(side=LEFT)
        else:
            self.password_label_extract.pack_forget()
            self.password_entry_extract.pack_forget()

    def select_cover_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp *.tiff")])
        if path:
            self.load_cover_image(path)

    def select_stego_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp *.tiff")])
        if path:
            self.load_stego_image(path)

    def load_cover_image(self, path):
        try:
            img = Image.open(path).convert('RGB')
            self.cover_image_path = path
            self.cover_image = img
            self.cover_image_label.config(text=os.path.basename(path), foreground="black")
            self.embed_button.config(state=NORMAL)
            self.status_var.set(f"Loaded cover image: {os.path.basename(path)}")
            
            
            thumbnail = img.copy()
            thumbnail.thumbnail((150, 150))
            self.cover_img_tk = ImageTk.PhotoImage(thumbnail)
            self.cover_image_preview.config(image=self.cover_img_tk)
            
            
            self.cover_image_preview.config(borderwidth=2, relief="solid")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")
            self.status_var.set("Error loading image")

    def load_stego_image(self, path):
        try:
            img = Image.open(path).convert('RGB')
            self.stego_image_path = path
            self.stego_image = img
            self.stego_image_label.config(text=os.path.basename(path), foreground="black")
            self.extract_button.config(state=NORMAL)
            self.status_var.set(f"Loaded stego image: {os.path.basename(path)}")
            
            
            thumbnail = img.copy()
            thumbnail.thumbnail((150, 150))
            self.stego_img_tk = ImageTk.PhotoImage(thumbnail)
            self.stego_image_preview.config(image=self.stego_img_tk)
            
            
            self.stego_image_preview.config(borderwidth=2, relief="solid")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")
            self.status_var.set("Error loading image")

    def on_cover_image_drop(self, event):
        path = event.data.strip('{}')
        if os.path.isfile(path):
            self.load_cover_image(path)

    def on_stego_image_drop(self, event):
        path = event.data.strip('{}')
        if os.path.isfile(path):
            self.load_stego_image(path)

    def embed_message(self):
        message = self.message_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to hide.")
            return
            
        if self.use_encryption.get():
            password = self.encryption_password.get()
            if not password:
                messagebox.showerror("Error", "Please enter an encryption password.")
                return
            key = get_fernet_key(password)
            try:
                message = encrypt_message(message, key)
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
                return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            title="Save image with hidden message"
        )
        
        if save_path:
            try:
                
                self.status_var.set("Hiding message in image...")
                self.root.update()
                
                embed_message_in_image(self.cover_image, message, save_path)
                
                messagebox.showinfo(
                    "Success!", 
                    f"Message successfully hidden in image!\nSaved to: {os.path.basename(save_path)}"
                )
                self.status_var.set("Message hidden successfully!")
                
                
                self.message_text.delete("1.0", tk.END)
                self.use_encryption.set(False)
                self.encryption_password.set("")
                self.toggle_password_entry()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to hide message: {e}")
                self.status_var.set("Error hiding message")

    def extract_message(self):
        try:
            
            self.status_var.set("Extracting message from image...")
            self.root.update()
            
            message = extract_message_from_image(self.stego_image)
            
            if self.use_encryption_extract.get():
                password = self.encryption_password_extract.get()
                if not password:
                    messagebox.showerror("Error", "Please enter the decryption password.")
                    return
                key = get_fernet_key(password)
                try:
                    message = decrypt_message(message, key)
                except InvalidToken:
                    messagebox.showerror("Error", "Incorrect password or corrupted data.")
                    return

            self.extracted_text.config(state=NORMAL)
            self.extracted_text.delete("1.0", tk.END)
            self.extracted_text.insert("1.0", message)
            self.extracted_text.config(state=DISABLED)
            self.status_var.set("Message revealed successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reveal message: {e}")
            self.status_var.set("Error revealing message")

root = TkinterDnD.Tk()
app = SteganographyApp(root)
root.mainloop()