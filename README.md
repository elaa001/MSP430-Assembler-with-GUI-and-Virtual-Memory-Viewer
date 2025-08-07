# 🧠 MSP430 Assembler with GUI & Virtual Memory Simulation

A two-pass assembler for a simplified MSP430 microcontroller, written in Python.  
It translates assembly code into machine code, simulates section-aware memory using `.ORG`, supports macros, and provides a full-featured GUI for interactive development and visualization.

---

## 🚀 Features

✅ **Two-Pass Assembler**  
- First pass: Label resolution, macro expansion, symbol/literal table creation  
- Second pass: Machine code generation, object file creation  

✅ **Supported Directives**  
- `.ORG` — manual address placement (used instead of `.sect`)  
- `.BYTE`, `.ASCII`, `.STRINGZ` — for defining data  
- `.DEFINE`, `.EQU`, `.ASG` — symbolic constant definitions  

✅ **Macro Support**  
- User-defined macros can be created and reused  
- Macro expansion occurs before pass 1

✅ **Virtual Memory Management**  
- Simulated `.text`, `.data`, `.bss` memory regions using `.ORG`  
- Automatic address tracking per section  
- Displays full memory map and layout

✅ **GUI Interface (Tkinter)**  
- Load `.asm` files
- View source code and assembled output
- See symbol and literal tables
- Visualize virtual memory layout  
- Save object files (`.hex`, `.obj`) for later use

✅ **Error Handling**  
- Invalid instructions, redefined labels, memory overflow, and undefined symbols are caught with meaningful messages.

---

## 📁 Project Structure
```
├── assembler_code.py     # Main assembler logic (two-pass)
├── interface.py          # GUI built with Tkinter
├── main.asm              # Demo input file 
├── output.hex            # Assembled machine code
├── MSP430.obj            # Object file
└── output_objs/          # Section-wise output files
```
---

## 🧪 Sample Input (Assembly)

```asm
.DEFINE SIZE 4
.EQU MASK 0xFF
.ASG 0xC000, RESET

.ORG 0xC000   ; .text
MOV.W #DATA_START, R4
MOV.W #BUFFER, R5
MOV.W #SIZE, R6
LOOP:
    MOV.B @R4+, R7
    AND.B #MASK, R7
    MOV.B R7, 0(R5)
    INC R5
    DEC R6
    JNZ LOOP
    NOP

.ORG 0xD000   ; .data
DATA_START:
    .BYTE 0x12, 0x34, 0xAB, 0xCD
    .ASCII "OK"
    .STRINGZ "Done!"

.ORG 0xE000   ; .bss
BUFFER:
    .BYTE 0, 0, 0, 0
````
---
🖥 How to Run
1. Install Python 3.8+ (with tkinter)
2. Clone or download the project
3. Run the GUI:
```
python interface.py
```
4. In the GUI:
  * Load a .asm file (like main.asm)
  * Click Assemble
  * View:
    - Assembled object code
    - Symbol & literal tables
    - Memory content
    - Output files: output.hex, MSP430.obj


