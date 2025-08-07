import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import re

# ─────────────────────────────────────────────────────────────
#  Global paths / constants used throughout the interface
# ─────────────────────────────────────────────────────────────
OBJ_DIR   = "output_objs"                     # where .text.obj, .data.obj … are placed
LINK_FILE = os.path.join(OBJ_DIR, "linked_output.hex")   # final linked HEX file

from assembler_code import (
    preprocess_defines,
    process_conditionals,
    preprocess_macros,
    pass1,
    pass2,
    write_object_file,
    read_assembly_output,
    define_table,
    parse_line,
    write_section_object_files_hex_format,
    virtual_memory
)


def highlight(event=None):
    # Önce eski etiketleri temizle
    for tag in ["directive", "opcode", "register",
                "immediate", "label", "comment"]:
        text_input.tag_remove(tag, "1.0", tk.END)

    # ► Tüm direktifleri tek REGEX’te topla
    #    . ile başlayan ve harf/rakam/_ içeren bütün kelimeyi yakalar
    dir_pat = re.compile(r'\.[A-Za-z_][A-Za-z0-9_]*')

    lines = text_input.get("1.0", tk.END).splitlines()
    for i, line in enumerate(lines, start=1):
        idx = f"{i}.0"

        # ───── Direktifler (tamamı yeşil) ─────
        for m in dir_pat.finditer(line):
            start, end = m.span()
            text_input.tag_add("directive",
                               f"{idx}+{start}c",
                               f"{idx}+{end}c")

        # ───── Etiket (LABEL:) ─────
        if ":" in line:
            label = line.split(":")[0]
            text_input.tag_add("label", idx, f"{idx}+{len(label)}c")

        # ───── Opcode’lar (MOV/ADD/…) ─────
        for word in ["MOV", "ADD", "SUB", "JMP",
                     "INC", "DEC", "TST", "CLR",
                     "RET", "CALL", "PUSH"]:
            pos = line.upper().find(word)
            if pos != -1:
                text_input.tag_add("opcode",
                                   f"{idx}+{pos}c",
                                   f"{idx}+{pos+len(word)}c")

        # ───── Register’ler (R0-R15) ─────
        for m in re.finditer(r"\bR\d+\b", line):
            s, e = m.span()
            text_input.tag_add("register",
                               f"{idx}+{s}c",
                               f"{idx}+{e}c")

        # ───── Immediate (#0x1234, #42) ─────
        for m in re.finditer(r"#0x[0-9A-Fa-f]+|#\d+", line):
            s, e = m.span()
            text_input.tag_add("immediate",
                               f"{idx}+{s}c",
                               f"{idx}+{e}c")

        # ───── Yorumlar (;) ─────
        com_pos = line.find(";")
        if com_pos != -1:
            text_input.tag_add("comment",
                               f"{idx}+{com_pos}c",
                               f"{idx}+{len(line)}c")


def show_msp430_info():
    popup = tk.Toplevel(root)
    popup.title("MSP430 Hakkında Bilgi")
    popup.geometry("800x600")
    popup.configure(bg="black")

    title = tk.Label(popup, text="🧠 MSP430 Bilgi Penceresi", font=("Helvetica", 16, "bold"), fg="#c084fc", bg="black")
    title.pack(pady=10)

    frame = tk.Frame(popup, bg="black")
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_area = tk.Text(frame, wrap=tk.WORD, yscrollcommand=scrollbar.set,
                        bg="#111111", fg="#e0e0e0", font=("Courier New", 10), insertbackground="white")
    text_area.pack(fill=tk.BOTH, expand=True)

    scrollbar.config(command=text_area.yview)

    info_text = """
🛠️ Geliştirme Araçları
- Assembler: Assembly kodunu makine koduna dönüştürür.
- Linker: Objeleri birleştirip çalıştırılabilir hale getirir.
- Archiver: Objeleri kütüphane olarak saklar.
- Hex Converter: HEX formatına dönüştürür.
- Disassembler: Makine kodunu çözümleyerek tekrar assembly'e döner.
- Strip Utility: Gereksiz sembolleri siler.

📦 Obje Dosyası (ELF Formatı)
- .text → Kod
- .data → Başlatılmış veri
- .bss  → Başlatılmamış veri
- .const, .cinit, .stack gibi ek bölümler de bulunur.

🧩 Assembler Direktifleri
- .text, .data, .bss: Segment tanımı
- .sect, .usect: Özel bölüm oluşturma
- .org: Bellek adresi belirleme
- .byte, .word, .ascii, .stringz: Veri tanımlama
- .define, .equ: Makro/sabit tanımı
- .global, .ref: Sembol görünürlüğü

🔢 Semboller ve Literaller
- Sabitler: #0x12, 42 gibi doğrudan değerler
- Semboller: Etiketler ve isimler
- Yerel semboller: ?1, ?2 gibi geçici etiketler

🔄 Linkleme
- MEMORY ve SECTIONS ile bellek yerleşimi yapılır.
- Objeler birleştirilip adresleme uygulanır.

🔧 HEX Dönüştürme
- .obj → .hex için hex430 veya benzeri kullanılır.
- Desteklenen formatlar: TI-TXT, Intel-HEX, Motorola-S

💡 Öneriler
- Kodlarınızı .text bölümüne yazın
- Verileri .data / .bss içinde tutun
- .org ile konum kontrolü yapın
- .usect ile özel RAM yapıları oluşturabilirsiniz
    """
    text_area.insert(tk.END, info_text)
    text_area.config(state=tk.DISABLED)

from assembler_code import linker, loader 

def open_linker_loader_window():
    popup = tk.Toplevel(root)
    popup.title("🔗 Linker / Loader")
    popup.geometry("400x250")
    popup.configure(bg="black")

    tk.Label(
        popup, text="Linker / Loader Panel",
        font=("Helvetica", 16, "bold"), fg="#c084fc", bg="black"
    ).pack(pady=10)

    # --- helpers --------------------------------------------------
    def run_linker():
        try:
            linker(input_dir=OBJ_DIR, output_file=LINK_FILE)
            #  🔽  remove the next line if you no longer want the HEX viewer
            # show_linked_hex()
            messagebox.showinfo("Linker", "✅ Linking başarılı!")
        except Exception as e:
            messagebox.showerror("Linker Error", str(e))

    def run_loader():
        try:
            loader(input_file=LINK_FILE)
            show_virtual_memory()
            messagebox.showinfo("Loader", "✅ Loading başarılı! Sanal bellek yüklendi.")
        except Exception as e:
            messagebox.showerror("Loader Error", str(e))

    # --- buttons --------------------------------------------------
    tk.Button(
        popup, text="🔗 Run Linker", font=("Helvetica", 12),
        command=run_linker, bg="#1E90FF", fg="white",
        activebackground="#a855f7"
    ).pack(pady=12)

    tk.Button(
        popup, text="📥 Run Loader", font=("Helvetica", 12),
        command=run_loader, bg="#1E90FF", fg="white",
        activebackground="#a855f7"
    ).pack(pady=12)


def animate_hover_in(widget, start=0):
    colors = ['#1E90FF', '#3887ff', '#5280ff', '#6b78ff', '#8571ff', '#9e69ff', '#a855f7']
    if start < len(colors):
        widget.config(bg=colors[start])
        widget.after(30, lambda: animate_hover_in(widget, start + 1))

def animate_hover_out(widget, start=0):
    colors = ['#a855f7', '#9e69ff', '#8571ff', '#6b78ff', '#5280ff', '#3887ff', '#1E90FF']
    if start < len(colors):
        widget.config(bg=colors[start])
        widget.after(30, lambda: animate_hover_out(widget, start + 1))

def assemble_and_display():
    source_code = text_input.get("1.0", tk.END).strip()
    if not source_code:
        messagebox.showerror("Hata", "Lütfen assembly kodunu girin.")
        return

    # ── FULL PRE-PROCESSING PIPELINE ───────────────────────────
    program = source_code.splitlines()
    program = preprocess_defines(program)
    program = process_conditionals(program)      # .IFDEF / .ELSE / .ENDIF
    program = preprocess_macros(program)         # .MACRO / .ENDM

    try:
        # 1️⃣  Pass-1  →  symbol & address tables
        symbol_table, addresses, literal_table = pass1(program)

        # 2️⃣  Pass-2  →  machine code (addr, value, size)
        machine_code = pass2(program, symbol_table, addresses, literal_table)

        # Section-level .obj files (.text.obj, .data.obj, …)
        write_section_object_files_hex_format("output_objs")   # <- <== new argument
    
        

        # Build *output.hex* and then convert it to a single MSP430.obj
        instructions = read_assembly_output("output.hex")     # [(addr, word)]
        write_object_file("MSP430", instructions)             

        # 🔗 Link the section .obj files into one final HEX
        from assembler_code import linker  # make sure this is imported
        linker(input_dir="output_objs", output_file="linked_output.hex")

        # ── GUI PANES ─────────────────────────────────────────
        text_output_hex.delete("1.0", tk.END)
        for addr, code in instructions:
            text_output_hex.insert(tk.END, f"{addr:04X}: {code}\n")

        symbol_output.delete("1.0", tk.END)
        for label, addr in symbol_table.items():
            symbol_output.insert(tk.END, f"{label}: {addr:04X}\n")

        define_output.delete("1.0", tk.END)
        for label, value in define_table.items():
            define_output.insert(tk.END, f"{label}: {value}\n")

        obj_output.delete("1.0", tk.END)
        if os.path.exists("MSP430.obj"):
            with open("MSP430.obj", "r") as f:
                obj_output.insert(tk.END, f.read())

        highlight()  # re-run syntax colouring

        # Refresh per-section views
        root.after(100, lambda: display_section_obj("text"))
        root.after(200, lambda: text_section_output.insert(tk.END, "\n---\n"))
        root.after(250, lambda: display_section_obj("data"))
        root.after(250, lambda: display_section_obj("bss"))

        messagebox.showinfo("Başarılı", "Çeviri başarıyla tamamlandı.")

    except Exception as e:
        messagebox.showerror("Hata", str(e))


        
def open_obj_popup():
    popup = tk.Toplevel(root)
    popup.title("Obj Dosyaları")
    popup.geometry("600x500")
    popup.configure(bg="black")

    button_frame = tk.Frame(popup, bg="black")
    button_frame.pack(pady=10)

    text_area = tk.Text(popup, height=30, width=70, bg="#111111", fg="white", font=("Courier New", 10))
    text_area.pack(padx=10, pady=10)

    def load_section(name):
        filepath = f"output_objs/{name}.obj"
        text_area.delete("1.0", tk.END)
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                text_area.insert(tk.END, f.read())
        else:
            text_area.insert(tk.END, f"{name}.obj bulunamadı.")

    tk.Button(button_frame, text="text", command=lambda: load_section("text"), bg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="data", command=lambda: load_section("data"), bg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="bss", command=lambda: load_section("bss"), bg="white").pack(side=tk.LEFT, padx=5)

def save_output():
    content = text_output_hex.get("1.0", tk.END)
    file_path = filedialog.asksaveasfilename(defaultextension=".hex", filetypes=[("HEX files", "*.hex")])
    if file_path:
        with open(file_path, "w") as f:
            f.write(content)
        messagebox.showinfo("Kaydedildi", f"HEX \u00e7\u0131kt\u0131s\u0131 kaydedildi:\n{file_path}")

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Assembly files", "*.asm *.txt")])
    if file_path:
        with open(file_path, "r") as f:
            text_input.delete("1.0", tk.END)
            text_input.insert(tk.END, f.read())
        highlight()
        
def display_section_obj(section_name):
    filepath = f"output_objs/{section_name}.obj"
    text_section_output.delete("1.0", tk.END)
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            text_section_output.insert(tk.END, f.read())
    else:
        text_section_output.insert(tk.END, f"{section_name}.obj bulunamadı.")
def show_virtual_memory():
    popup = tk.Toplevel(root)
    popup.title("🧠 Sanal Bellek (Virtual Memory)")
    popup.geometry("600x500")
    popup.configure(bg="black")

    text_area = tk.Text(popup, bg="#111111", fg="white", font=("Courier New", 10))
    text_area.pack(fill=tk.BOTH, expand=True)

    sorted_mem = sorted(virtual_memory.items())
    for addr, val in sorted_mem:
        if isinstance(val, tuple):  # (value, section)
            v, s = val
            text_area.insert(tk.END, f"{addr:04X}: {v:02X}    ; section = {s}\n")
        else:
            text_area.insert(tk.END, f"{addr:04X}: {val:02X}\n")
def show_linked_hex():
    popup = tk.Toplevel(root)
    popup.title("🔗 Linked HEX")
    popup.geometry("600x500")
    popup.configure(bg="black")

    txt = tk.Text(popup, bg="#111111", fg="white", font=("Courier New", 10))
    txt.pack(fill=tk.BOTH, expand=True)

    try:
        if os.path.isfile(LINK_FILE) and os.path.getsize(LINK_FILE) > 0:
            with open(LINK_FILE, "r") as f:
                txt.insert(tk.END, f.read())
        else:
            txt.insert(tk.END, f"Dosya bulunamadı veya boş:\n{LINK_FILE}")
    except Exception as e:
        txt.insert(tk.END, f"Hata: {e}")

    txt.config(state=tk.DISABLED)


root = tk.Tk()
root.title("\U0001f6e0\ufe0f MSP430 Assembly Derleyici")
root.attributes('-fullscreen', True)
root.configure(bg="black")
root.bind("<Escape>", lambda e: root.attributes('-fullscreen', False))

main_frame = tk.Frame(root, bg="black")
main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)
main_frame.rowconfigure(0, weight=1)

left_frame = tk.Frame(main_frame, bg="black")
left_frame.grid(row=0, column=0, sticky="n")

label_style = {
    "bg": "black",
    "fg": "#c084fc",
    "font": ("Helvetica", 15, "bold"),
    "anchor": "w",
    "padx": 5,
    "pady": 5
}

label_input = tk.Label(left_frame, text="Assembly Kodunuzu Girin:", **label_style)
label_input.pack()

text_input = tk.Text(left_frame, height=30, width=70, font=("Courier New", 11), bg="#111111", fg="#f3f3f3", insertbackground="#c084fc")
text_input.pack(padx=5, pady=5)
text_input.bind("<KeyRelease>", highlight)

text_input.tag_config("directive", foreground="#3a7d44")
text_input.tag_config("opcode", foreground="#c084fc")
text_input.tag_config("register", foreground="#60a5fa")
text_input.tag_config("immediate", foreground="#eab308")
text_input.tag_config("label", foreground="#f43f5e")
text_input.tag_config("comment", foreground="#9ca3af", font=("Courier New", 10, "italic"))

btn_frame = tk.Frame(left_frame, bg="black")
btn_frame.pack(pady=10)

style = ttk.Style()
style.theme_use("default")
style.configure("Custom.TButton", background="#1E90FF", foreground="white", font=("Helvetica", 13, "bold"), borderwidth=0, padding=6)
style.map("Custom.TButton",
    background=[("active", "#a855f7")],
    foreground=[("active", "white")],
    font=[("active", ("Helvetica", 10, "bold"))],
    padding=[("active", 8)],
    relief=[("active", "raised")]
)
style.configure("Treeview", background="#111111", foreground="white", fieldbackground="#111111", borderwidth=0)
style.map("Treeview", background=[('selected', '#4b0082')])

btn_open = ttk.Button(btn_frame, text="Dosya A\u00e7", command=open_file, style="Custom.TButton")
btn_open.pack(side=tk.LEFT, padx=10)
btn_compile = ttk.Button(btn_frame, text="\u25b6 Derle", command=assemble_and_display, style="Custom.TButton")
btn_compile.pack(side=tk.LEFT, padx=10)
btn_save = ttk.Button(btn_frame, text="Kaydet", command=save_output, style="Custom.TButton")
btn_save.pack(side=tk.LEFT, padx=10)

label_define = tk.Label(left_frame, text=".DEFINE / .SET Tablosu:", **label_style)
label_define.pack()
define_output = tk.Text(left_frame, height=8, width=70, font=("Courier New", 11), bg="#111111", fg="white", insertbackground="#c084fc")
define_output.pack(padx=5, pady=5)

right_frame = tk.Frame(main_frame, bg="black")
right_frame.grid(row=0, column=1, sticky="n")

label_hex = tk.Label(right_frame, text="Makine Kodu (HEX):", **label_style)
label_hex.pack()
text_output_hex = tk.Text(right_frame, height=10, width=70, font=("Courier New", 15, "bold"), bg="#111111", fg="white", insertbackground="#c084fc")
text_output_hex.pack(padx=5, pady=5)

label_symbol = tk.Label(right_frame, text="Sembol Tablosu:", **label_style)
label_symbol.pack()
symbol_output = tk.Text(right_frame, height=9, width=70, font=("Courier New", 10), bg="#111111", fg="white", insertbackground="#c084fc")
symbol_output.pack(padx=5, pady=5)

label_obj = tk.Label(right_frame, text=".OBJ Çıktısı:", **label_style)
label_obj.pack()
obj_output = tk.Text(right_frame, height=9, width=70, font=("Courier New", 10), bg="#111111", fg="white", insertbackground="#c084fc")
obj_output.pack(padx=5, pady=5)



tk.Label(right_frame, text="Section Object Dosyası:", bg="black", fg="#c084fc", font=("Helvetica", 15, "bold"), anchor="w", padx=5, pady=5).pack()
section_button_frame = tk.Frame(right_frame, bg="black")
section_button_frame.pack(pady=(10, 0))

ttk.Button(section_button_frame, text="text", command=lambda: display_section_obj("text"), style="Custom.TButton").pack(side=tk.LEFT, padx=5)
ttk.Button(section_button_frame, text="data", command=lambda: display_section_obj("data"), style="Custom.TButton").pack(side=tk.LEFT, padx=5)
ttk.Button(section_button_frame, text="bss", command=lambda: display_section_obj("bss"), style="Custom.TButton").pack(side=tk.LEFT, padx=5)

text_section_output = tk.Text(right_frame, height=10, width=70, font=("Courier New", 10), bg="#111111", fg="white", insertbackground="#c084fc", state=tk.NORMAL)
text_section_output.pack(padx=5, pady=5)

info_frame = tk.Frame(root, bg="black")
info_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

info_label = tk.Label(info_frame, text="MSP430 nedir?", font=("Helvetica", 16, "bold"), fg="#c084fc", bg="black")
info_label.pack(side=tk.LEFT, padx=10)

info_button = tk.Button(
    info_frame,
    text="Bilgi Göster",
    font=("Helvetica", 11, "bold"),
    bg="#1E90FF",
    fg="white",
    bd=0,
    padx=10,
    pady=6,
    activeforeground="white",
    activebackground="#a855f7",
    cursor="hand2",
    command=show_msp430_info
)
info_button.pack(side=tk.LEFT, padx=5)
info_button.bind("<Enter>", lambda e: animate_hover_in(info_button))
info_button.bind("<Leave>", lambda e: animate_hover_out(info_button))

linker_loader_btn = tk.Button(
    info_frame,
    text="Linker / Loader",
    font=("Helvetica", 11, "bold"),
    bg="#1E90FF",
    fg="white",
    bd=0,
    padx=10,
    pady=6,
    activeforeground="white",
    activebackground="#a855f7",
    cursor="hand2",
    command=open_linker_loader_window
)
linker_loader_btn.pack(side=tk.RIGHT, padx=10)

# --- Bottom-bar buttons -------------------------------------------------
btn_show_memory = tk.Button(
    info_frame,
    text="Sanal Bellek",
    font=("Helvetica", 11, "bold"),
    bg="#1E90FF", fg="white",
    bd=0, padx=10, pady=6,
    activeforeground="white", activebackground="#a855f7",
    cursor="hand2",
    command=show_virtual_memory
)
btn_show_memory.pack(side=tk.RIGHT, padx=10)

btn_show_linked = tk.Button(
    info_frame,
    text="Linked HEX",
    font=("Helvetica", 11, "bold"),
    bg="#1E90FF",
    fg="white",
    bd=0,
    padx=10,
    pady=6,
    activeforeground="white",
    activebackground="#a855f7",
    cursor="hand2",
    command=show_linked_hex
)
btn_show_linked.pack(side=tk.RIGHT, padx=10)


root.mainloop()



