import re
import os
import ast
import math
import glob
from math import *
# MSP430 OPCODE TABLOSU
virtual_memory = {}
def read_memory(address):
    """ Verilen adresteki değeri döndür. """
    return virtual_memory.get(address, 0)

def write_memory(address, value, size=2):
    """ Belleğe veri yaz. 1 bayt veya 2 bayt olabilir (size parametresiyle). """
    if size == 1:
        virtual_memory[address] = value & 0xFF
    elif size == 2:
        # Little endian yaz: önce düşük bayt, sonra yüksek bayt
        virtual_memory[address] = value & 0xFF
        virtual_memory[address + 1] = (value >> 8) & 0xFF

opcode_table = {
    "MOV": 0x4000, "ADD": 0x5000, "SUB": 0x8000, "CMP": 0x9000,
    "BIC": 0xC000, "BIS": 0xD000, "XOR": 0xE000, "AND": 0xF000,
    "PUSH": 0x1200, "CALL": 0x1280, "JMP": 0x3C00, "RET": 0x4130,
    "NOP": 0x0000, "MOVI": 0x2000, "BR": 0x4030,
    "CLR": 0x4300,"INC": 0x5300,"DEC": 0x8300,"TST": 0x9300,
}

define_table = {}
exported_symbols = set()       # .DEF destekleyen satırdan
external_references = set()    # .REF destekleyen satırdan
macro_table = {}

# MSP430 LITERAL sabitleri (constant generator destekli)
msp430_literal_constants = {
    0: (3, 0),  # R3, As=0
    1: (3, 1),  # R3, As=1
    2: (3, 2),  # R3, As=2
    4: (3, 3),  # R3, As=3
    8: (2, 3),  # R2, As=3
   -1: (2, 2), # R2, As=2
}

def preprocess_defines(program):
    new_program = []

    for line in program:
        # Yorumları at
        line_clean = line.split(';')[0].strip()
        if not line_clean:
            continue

        tokens = line_clean.split()
        if not tokens:
            continue

        directive = tokens[0].upper()

        # .DEFINE, .EQU, .SET → define_table'a ekle
        if ".SET" in line_clean.upper():
            match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s+\.SET\s+(.*)', line_clean, re.IGNORECASE)
            if match:
                name = match.group(1).strip()
                value = match.group(2).strip()
                try:
                    define_table[name] = int(value, 0)
                except:
                    if value in define_table:
                        define_table[name] = define_table[value]
                    else:
                        define_table[name] = value
                continue  

        # Define değilse, satırı listeye ekle
        new_program.append(line)

    return new_program

def extract_macro_expressions(line):
    """Güvenli şekilde makro ifadelerini çıkarır"""
    results = []
    i = 0
    while i < len(line):
        if line[i:i+2] == "\\(":
            start = i + 2
            depth = 1
            j = start
            while j < len(line) and depth > 0:
                if line[j] == '(':
                    depth += 1
                elif line[j] == ')':
                    depth -= 1
                j += 1
            if depth == 0:
                expr = line[start:j-1]
                results.append((f"\\({expr})", expr))
                i = j
            else:
                raise ValueError(f"Eşleşmeyen parantez: {line[i:i+20]}...")
        else:
            i += 1
    return results

def safe_eval(expr, variables):
    """Güvenli matematiksel ifade değerlendirme"""
    allowed_names = {
        'sin': math.sin,
        'cos': math.cos,
        'tan': math.tan,
        'sqrt': math.sqrt,
        'pi': math.pi,
        'e': math.e,
        'abs': abs,
        'log': math.log,
        'log10': math.log10,
        'int': int,
        'float': float
    }

    # Tüm güvenli olmayan built-in'leri kaldır
    eval_locals = {'__builtins__': None}
    eval_locals.update(allowed_names)
    eval_locals.update(variables)
    
    return eval(expr, eval_locals)

def process_includes(program_lines, base_path="", included_files=None, depth=0, max_depth=10):
    """
    .include "dosya.asm" direktiflerini işler (recursive).
    - base_path: içeri alınan dosyaların göreli konumu
    - included_files: zaten yüklenmiş dosyaları takip eder (sonsuz döngü önleme)
    """
    if included_files is None:
        included_files = set()

    if depth > max_depth:
        raise RecursionError(f".include derinliği çok fazla (>{max_depth}) — döngü olabilir.")

    expanded_program = []

    for line in program_lines:
        stripped = line.strip()

        if stripped.lower().startswith(".include"):
            matches = re.findall(r'\.include\s+"([^"]+)"', stripped, re.IGNORECASE)
            if not matches:
                raise ValueError(f"Hatalı .include satırı: {line}")

            for include_file in matches:
                full_path = os.path.abspath(os.path.join(base_path, include_file))

                if full_path in included_files:
                    print(f"[SKIP] {include_file} daha önce eklendi — atlaniyor.")
                    continue

                if not os.path.isfile(full_path):
                    raise FileNotFoundError(f".include dosyasi bulunamadi: {full_path}")

                with open(full_path, "r", encoding="utf-8") as f:
                    included_lines = f.readlines()

                print(f"[INCLUDE] {include_file} dosyasi eklendi ({len(included_lines)} satir)")
                included_files.add(full_path)

                # Recursive include
                included_expanded = process_includes(
                    included_lines,
                    base_path=os.path.dirname(full_path),
                    included_files=included_files,
                    depth=depth + 1,
                    max_depth=max_depth
                )
                expanded_program.extend(included_expanded)
        else:
            expanded_program.append(line)

    return expanded_program

def process_conditionals(program_lines):
    """ .ifdef / .ifndef / .else / .endif bloklarını işler (makro dışında) """
    output = []
    stack = []
    inside_macro = False

    for line in program_lines:
        stripped = line.strip()
        upper = stripped.upper()

        # Makro tanımının başladığı ve bittiği yerleri takip et
        if upper.startswith(".MACRO"):
            inside_macro = True
        elif upper.startswith(".ENDM"):
            inside_macro = False

        if inside_macro:
            output.append(line)
            continue
      
        if upper.startswith(".IFDEF"):
            tokens = stripped.split()
            if len(tokens) < 2:
                raise ValueError(".ifdef eksik argüman")
            symbol = tokens[1].upper()  # ← BURAYI EKLE
            condition = symbol in define_table
            stack.append({"active": condition, "else_seen": False})
            continue

        elif upper.startswith(".IFNDEF"):
            tokens = stripped.split()
            if len(tokens) < 2:
                raise ValueError(".ifndef eksik argüman")
            symbol = tokens[1].upper()  # ← BURAYI EKLE
            condition = symbol not in define_table
            stack.append({"active": condition, "else_seen": False})
            continue

        elif upper.startswith(".ELSE"):
            if not stack:
                raise ValueError(".ELSE ifadesi ama aktif .IFDEF/.IFNDEF yok")
            if stack[-1]["else_seen"]:
                raise ValueError("Bir .IFDEF/.IFNDEF bloğunda birden fazla .ELSE kullanilamaz")
            stack[-1]["active"] = not stack[-1]["active"]
            stack[-1]["else_seen"] = True
            continue

        elif upper.startswith(".ENDIF"):
            if not stack:
                raise ValueError(".ENDIF fazladan veya eşleşmedi")
            stack.pop()
            continue

        # Normal satır
        if not stack or all(ctx["active"] for ctx in stack):
            output.append(line)

    if stack:
        raise ValueError(".ENDIF eksik — açik kalan .IFDEF/.IFNDEF bloğu var")

    return output

def process_macro_conditionals(lines, arg_map):
    """Makro içinde .if/.else/.endif destekleyen koşullu blokları işler"""
    output = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        upper = line.upper()

        if upper.startswith('.IF'):
            condition_expr = line[3:].strip()
            true_block, false_block = [], []
            i += 1
            depth = 1
            inside_else = False
            while i < len(lines) and depth > 0:
                curr = lines[i].strip()
                if curr.upper().startswith('.IF'):
                    depth += 1
                elif curr.upper().startswith('.ENDIF'):
                    depth -= 1
                    if depth == 0:
                        break
                elif curr.upper().startswith('.ELSE') and depth == 1:
                    inside_else = True
                    i += 1
                    continue

                if not inside_else:
                    true_block.append(lines[i])
                else:
                    false_block.append(lines[i])
                i += 1

            # Makro argümanlarını yerine koy
            expr = condition_expr
            for p, a in arg_map.items():
                expr = expr.replace(f'\\{p}', a)

            result = safe_eval(expr, arg_map)
            try:
                if result:
                    output.extend(true_block)
                else:
                    output.extend(false_block)
            except:
                raise ValueError(f".IF koşulu değerlendirilemedi: {expr}")

        else:
            output.append(lines[i])
        i += 1
    return output

def preprocess_macros(program, depth=0, max_depth=10):
    if depth > max_depth:
        raise RecursionError(f"Maksimum makro derinliği aşildi ({max_depth})")

    global macro_table
    if depth == 0:
        macro_table.clear()

    expanded_program = program[:]

    # Makro tanımlarını işle
    i = 0
    while i < len(expanded_program):
        line = expanded_program[i].split(';')[0].strip()
        if line.upper().startswith(".MACRO"):
            tokens = line.split()
            if len(tokens) < 2:
                raise ValueError("Makro adi eksik")
                
            macro_name = tokens[1].upper()
            params = [p.strip(',') for p in tokens[2:]]
            
            # Parametre doğrulama
            for param in params:
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', param):
                    raise ValueError(f"Geçersiz parametre adi: '{param}'")

            body = []
            nesting = 1
            i += 1
            while i < len(expanded_program) and nesting > 0:
                curr_line = expanded_program[i]
                clean = curr_line.split(';')[0].strip().upper()
                if clean.startswith(".MACRO"):
                    nesting += 1
                elif clean.startswith(".ENDM"):
                    nesting -= 1
                    if nesting == 0:
                        break
                body.append(curr_line.rstrip('\n'))
                i += 1

            if nesting != 0:
                raise ValueError(".ENDM eksik")

            unique_id = f"{macro_name}_{i}"
            processed_lines = []
            for macro_line in body:
                replaced = re.sub(r'%%([a-zA-Z_][a-zA-Z0-9_]*)', rf'{unique_id}_\1', macro_line)
                processed_lines.append(replaced)

            macro_table[macro_name] = (params, processed_lines)

            expanded_program = expanded_program[:i - len(body) - 1] + expanded_program[i + 1:]
            i = 0  # Program değişti, baştan başla
        else:
            i += 1

    # Makro çağrılarını genişlet
    changed = True
    while changed:
        changed = False
        new_program = []
        for line in expanded_program:
            original = line
            line_clean = line.split(';')[0].strip()
            if not line_clean:
                new_program.append(original)
                continue

            tokens = line_clean.split()
            label = None
            if tokens and tokens[0].endswith(':'):
                label = tokens[0][:-1]
                tokens = tokens[1:]

            if tokens and tokens[0].upper() in macro_table:
                macro_name = tokens[0].upper()
                args = [a.strip(',') for a in tokens[1:]]
                params, body = macro_table[macro_name]

                if len(args) != len(params):
                    expected = ", ".join(params)
                    received = ", ".join(args) if args else "(none)"
                    raise ValueError(
                        f"Makro '{macro_name}' için yanliş argüman sayisi\n"
                        f"Beklenen: {len(params)} ({expected})\n"
                        f"Alinan: {len(args)} ({received})"
                    )

                arg_map = dict(zip(params, args))
                processed_body = process_macro_conditionals(body, arg_map)
                for macro_line in processed_body:
                    expanded = macro_line
                    
                    # Önce parametre değişimlerini yap
                    for param, arg in arg_map.items():
                        expanded = expanded.replace(f"\\{param}", arg)
                        patterns = [
                            (rf'\#{re.escape(param)}\b', f"#{arg}"),
                            (rf'\&{re.escape(param)}\b', f"&{arg}"),
                            (rf'\b{re.escape(param)}\b', arg),
                        ]
                        for pattern, replacement in patterns:
                            expanded = re.sub(pattern, replacement, expanded)

                    # Matematiksel ifadeleri işle
                    try:
                        eval_matches = extract_macro_expressions(expanded)
                        for full, expr in eval_matches:
                            # Parametre değerlerini yerine koy
                            safe_expr = expr
                            for p, a in arg_map.items():
                                safe_expr = safe_expr.replace(p, a)
                            
                            # Güvenli değerlendirme
                            value = safe_eval(safe_expr, arg_map)
                            expanded = expanded.replace(full, str(value))
                    except ValueError as e:
                        raise ValueError(f"{macro_name} makrosunda: {str(e)}")

                    # Eğer expanded satırı yeni bir makro çağrısıysa ve recursive durdurma gerekiyorsa
                    recursive_call_match = re.match(rf"^\s*{macro_name}\s+(.+)", expanded, re.IGNORECASE)
                    if recursive_call_match:
                        try:
                            arg_expr = recursive_call_match.group(1).strip()
                            val = safe_eval(arg_expr, arg_map)
                            if float(val) <= 0:
                                continue  # Recursive çağrıyı durdur
                        except:
                            pass  # değerlendirilemiyorsa yine de dene

                    if label:
                        expanded = f"{label}: {expanded}"
                        label = None

                    # Recursive genişletme
                    if depth + 1 <= max_depth:
                        try:
                            inner_expanded = preprocess_macros([expanded], depth + 1, max_depth)
                            new_program.extend(inner_expanded)
                        except RecursionError as e:
                            raise RecursionError(f"{macro_name} makrosunda: {str(e)}")
                    else:
                        new_program.append(expanded)
                
                changed = True
            else:
                new_program.append(original)

        expanded_program = new_program

    return expanded_program

def parse_data_directive(parsed, line):
    line_upper = line.upper()

    # === .ASCII "HELLO" ===
    if '.ASCII' in line_upper:
        match = re.search(r'\.ASCII\s+"([^"]+)"', line, re.IGNORECASE)
        if match:
            parsed["data"] = [ord(c) for c in match.group(1)]
        return parsed

    # === .ASCIZ "HELLO" → null-terminated ===
    if '.ASCIZ' in line_upper or '.STRINGZ' in line_upper:
        match = re.search(r'\.(ASCIZ|STRINGZ)\s+"([^"]+)"', line, re.IGNORECASE)
        if match:
            parsed["data"] = [ord(c) for c in match.group(2)] + [0]
        return parsed

    # === .BYTE 0x12, 0x34, 255 ===
    if '.BYTE' in line_upper:
        match = re.search(r'\.BYTE\s+(.+)', line, re.IGNORECASE)
        if match:
            values = match.group(1).split(',')
            parsed["data"] = [int(define_table[v.strip()], 0) if v.strip() in define_table else int(v.strip(), 0) for v in values]

        return parsed

    # === .WORD 0x1234, 42 ===
    if '.WORD' in line_upper:
        match = re.search(r'\.WORD\s+(.+)', line, re.IGNORECASE)
        if match:
            values = match.group(1).split(',')
            parsed["data"] = [int(v.strip(), 0) for v in values]
        return parsed

    # === .FILL val, count ===
    if '.FILL' in line_upper:
        match = re.search(r'\.FILL\s+(\d+)\s*,\s*(\d+)', line, re.IGNORECASE)
        if match:
            value = int(match.group(1))
            count = int(match.group(2))
            parsed["data"] = [value] * count
        return parsed
    # === .WORD VALUE1, 0xFFEE ===
    if '.WORD' in line_upper:
        match = re.search(r'\.WORD\s+(.+)', line, re.IGNORECASE)
        if match:
            values = match.group(1).split(',')
            parsed["data"] = [
                int(define_table[v.strip()], 0) if v.strip() in define_table else int(v.strip(), 0)
                for v in values
            ]

    return parsed

# Section bilgilerini tutan yapı
section_info = {
    ".text": {
        "start_address": 0x0000,
        "current_address": 0x0000,
        "content": []
    },
    ".data": {
        "start_address": 0x0200,
        "current_address": 0x0200,
        "content": []
    },
    ".bss": {
        "start_address": 0x0400,
        "current_address": 0x0400,
        "content": []
    }
}

current_section = ".text"  # Başlangıç varsayılanı

def set_section(section_name, address=None):
    global current_section
    if not re.match(r'^\.[a-zA-Z_][a-zA-Z0-9_.]*$', section_name):
        raise ValueError(f"Invalid section name: {section_name}")
    section_name = section_name.lower()
        
    if section_name not in section_info:
        if address is None:
            raise ValueError(f"Missing address for new section '{section_name}'")
        section_info[section_name] = {
            "start_address": address,
            "current_address": address,
            "content": []
        }
    else:
        # Section zaten varsa ve yeni adres verilmişse, mevcut adresleri güncelle
        if address is not None:
            address = int(address, 0) if isinstance(address, str) else address
            section_info[section_name]["start_address"] = address
            section_info[section_name]["current_address"] = address


    current_section = section_name
    return section_info[section_name]

def get_current_section():
    return section_info.get(current_section)

def increment_address(size):
    section = get_current_section()
    if section:
        before = section["current_address"]
        section["current_address"] += size
        print(f"[INCREMENT] {current_section}: {before:04X} + {size} → {section['current_address']:04X}")
        return section["current_address"]
    return None

def parse_line(line, symbol_table=None):
    global exported_symbols, external_references, current_section

    line = line.split(';')[0].strip()
    if not line:
        return None, "Empty line"
    
    line_upper=line.upper()
    
    if line_upper.startswith('.USECT'):
        # Format: .usect "section_name", size[, alignment]
        match = re.match(r'\.usect\s+"([^"]+)"\s*,\s*(\d+)\s*(?:,\s*(\d+))?', line, re.IGNORECASE)
        if match:
            return {
                "directive": "usect",
                "section": match.group(1),
                "size": int(match.group(2)),
                "alignment": int(match.group(3)) if match.group(3) else 1
            }, None
    # & işaretli operand işleme
    if '&' in line:
        parts = line.split()
        for i, part in enumerate(parts):
            if '&' in part and not part.startswith(';'):
                symbol = part[part.index('&')+1:].split(',')[0].strip()
                if symbol not in symbol_table and symbol not in define_table:
                    return None, f"Undefined symbol: {symbol}"
                        
    if line_upper.startswith('.BSS'):
        # .bss degisken_adi, boyut[, hizalama]
        match = re.match(r'\.bss\s+(\w+)\s*,\s*(\d+)\s*(?:,\s*(\d+))?', line, re.IGNORECASE)
        if match:
            parsed = {
                "directive": "bss",
                "symbol": match.group(1),
                "size": int(match.group(2)),
                "alignment": int(match.group(3)) if match.group(3) else 1
            }
            return parsed, None
        
    # SECTION: .text / .data / .bss / .sect "name" [adres]
    section_match = re.match(
    r'^\.(text|data|bss|sect)\s*(?:"([^"]+)"\s*)?(?:,\s*(\S+))?', line, re.IGNORECASE)
    if section_match:
        sect_type = section_match.group(1).lower()
        sect_name = section_match.group(2) if section_match.group(2) else f".{sect_type}"
        if not sect_name.startswith('.'):
            sect_name = f".{sect_name}"
        address = section_match.group(3)
        addr_value = int(address, 0) if address else None
        current_section = sect_name
        return {
            "directive": "section",
            "section": sect_name,
            "address": addr_value
        }, None
    
    if line.upper().startswith('.ORG'):
        parts = line.split()
        return {"directive": parts[0][1:].lower(), "operands": parts[1:]}, None
    
    # Diğer özel direktifler: .ORG, .END, .DEFINE, .EQU, .SET
    if line.upper().startswith(('.ORG', '.END', '.DEFINE', '.EQU', '.SET')):
        parts = line.split()
        return {"directive": parts[0][1:].lower(), "operands": parts[1:]}, None
    
    if '.SET' in line_upper:
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s+\.SET\s+(.*)', line, re.IGNORECASE)
        if match:
            label = match.group(1).strip()
            value_str = match.group(2).strip()
            try:
                value = int(value_str, 0)
            except:
                if value_str in define_table:
                    value = define_table[value_str]
                else:
                    return None, f"Cannot resolve SET value: {value_str}"
            define_table[label] = value
            return {"directive": "set", "label": label, "value": value}, None

    # .DEF / .REF
    if line.upper().startswith('.DEF'):
        symbols = [s.strip() for s in line[4:].split(',')]
        for sym in symbols:
            exported_symbols.add(sym)# ✅ BURASI ÖNEMLİ
        return {"directive": "def", "symbols": symbols}, None

    if line.upper().startswith('.REF'):
        symbols = [s.strip() for s in line[4:].split(',')]
        for sym in symbols:
            external_references.add(sym)
        return {"directive": "ref", "symbols": symbols}, None

    # .ALIGN
    if line.upper().startswith('.ALIGN'):
        match = re.search(r'\.ALIGN\s+(\d+)', line, re.IGNORECASE)
        if match:
            return {"opcode": ".ALIGN", "op1": match.group(1)}, None

    # .SPACE
    if line.upper().startswith('.SPACE'):
        match = re.search(r'\.SPACE\s+(\d+)', line, re.IGNORECASE)
        if match:
            return {"opcode": ".SPACE", "op1": match.group(1)}, None

    # Veri direktifleri
    parsed = {
        "label": None, "opcode": None, "op1": None, "op2": None,
        "is_immediate": False, "immediate_value": 0,
        "data": None, "use_literal_pool": False,
        "use_const_generator": False, "section": current_section
    }

    parts = line.split()
    if not parts:
        return None, "Invalid line"

    if ':' in parts[0]:
        parsed["label"] = parts[0].replace(':', '')
        parts = parts[1:]
        if not parts:
            return parsed, None

    directive_line = ' '.join(parts)
    if any(d in directive_line.upper() for d in [".ASCII", ".ASCIZ", ".BYTE", ".WORD", ".FILL"]):
        return parse_data_directive(parsed, directive_line), None
    
    # Pseudo-komutlar için özel çözüm
    if parsed["opcode"] == "CLR":
        parsed["is_immediate"] = True
        parsed["immediate_value"] = 0
        parsed["use_const_generator"] = True

    elif parsed["opcode"] == "INC" or parsed["opcode"] == "DEC":
        parsed["is_immediate"] = True
        parsed["immediate_value"] = 1
        parsed["use_const_generator"] = True

    elif parsed["opcode"] == "TST":
        parsed["is_immediate"] = True
        parsed["immediate_value"] = 0
        parsed["use_const_generator"] = True

    # Normal instruction
    opcode = parts[0].upper()
    parsed["opcode"] = opcode
    parsed["size"] = "W"
    if opcode.endswith(".B"):
        parsed["opcode"] = opcode[:-2]
        parsed["size"] = "B"
    elif opcode.endswith(".W"):
        parsed["opcode"] = opcode[:-2]

    if len(parts) > 1:
        operands = ''.join(parts[1:]).split(',')
        parsed["op1"] = operands[0] if len(operands) > 0 else None
        parsed["op2"] = operands[1] if len(operands) > 1 else None

    # .DEFINE çözümlemesi
    if parsed["op1"] in define_table:
        parsed["op1"] = str(define_table[parsed["op1"]])
    if parsed["op2"] in define_table:
        parsed["op2"] = str(define_table[parsed["op2"]])

    # Literal Pool: &etiket veya &0xVAL
    if parsed["op1"] and parsed["op1"].startswith('&'):
        val = parsed["op1"][1:]
        try:
            if val in symbol_table:
                parsed["immediate_value"] = symbol_table[val]
            elif val in define_table:
                parsed["immediate_value"] = define_table[val]
            else:
                parsed["immediate_value"] = int(val, 0)
            parsed["use_literal_pool"] = True
        except:
            return None, f"Address resolution failed for &{val}"


# Immediate: #VAL veya #DEFINE
    if parsed["op1"] and parsed["op1"].startswith('#'):
        val = parsed["op1"][1:]
        try:
            # Define tablosundan çöz
            if val in define_table:
                resolved = define_table[val]
                parsed["immediate_value"] = int(str(resolved), 0)

            else:
                parsed["immediate_value"] = int(val, 0)

            parsed["is_immediate"] = True

            # 🔍 Debug için ekle
            print(f"[PARSE] #{val} resolved to {parsed['immediate_value']}")

            # 🔧 Const generator kontrolü - EN KRİTİK KISIM!
            if parsed["immediate_value"] in msp430_literal_constants:
                parsed["use_const_generator"] = True
                print(f"[PARSE] using CONST GENERATOR for value #{parsed['immediate_value']}")
            else:
                parsed["use_const_generator"] = False
                print(f"[PARSE] using NORMAL IMMEDIATE for value #{parsed['immediate_value']}")
        except Exception as e:
            return None, f"Immediate value parse failed for {val}: {e}"

    return parsed, None

def detect_addressing_mode(operand):
    if not operand:
        return 0, 0, None  # varsayılan: R0, As=0

    operand = operand.strip()

    # === Indexed addressing: offset(Rx) ===
    match = re.match(r'(-?\d+)\(R(\d+)\)', operand)
    if match:
        offset = int(match.group(1))
        reg = int(match.group(2))
        return reg, 1, offset

    # === Autoincrement: @Rx+ ===
    match = re.match(r'@R(\d+)\+', operand)
    if match:
        reg = int(match.group(1))
        return reg, 3, None

    # === Indirect: @Rx ===
    match = re.match(r'@R(\d+)', operand)
    if match:
        reg = int(match.group(1))
        return reg, 2, None

    # === Register direct: Rx ===
    match = re.match(r'R(\d+)', operand)
    if match:
        reg = int(match.group(1))
        return reg, 0, None

    # === Immediate: #VAL (e.g., #1) ===
    if operand.startswith('#'):
        return 3, 3, None  # R3, As=11

    # === Literal adresleme: &LABEL ===
    if operand.startswith('&'):
        return 0, 0, None  # Literal → özel işleniyor

    # === Düz sayı (örneğin .DEFINE'den çözülmüş) ===
    if operand.isdigit():
        return 3, 3, None  # Literal gibi davran (#1234 → R3, As=11)

    # Hatalı tanım
    print(f"[WARNING] Unknown addressing mode: {operand}")
    return 0, 0, None


def instruction_length(parsed, current_address):
    if not parsed:
        return 0

    # .SPACE → belirtilen byte kadar yer ayır
    if parsed.get("opcode") == ".SPACE":
        op1 = parsed.get("op1")
        try:
            size = int(op1, 0)
        except ValueError:
            if op1 in define_table:
                size = int(define_table[op1], 0) if isinstance(define_table[op1], str) else define_table[op1]
            else:
                raise ValueError(f".SPACE operand '{op1}' is not a valid number or defined symbol.")
        return size, (current_address + size if current_address is not None else None)

    # .ALIGN → adresi hizala
    if parsed.get("opcode") == ".ALIGN":
        align_to = int(parsed.get("op1"))
        if current_address is None:
            raise ValueError(".ALIGN used without current address")
        padding = (align_to - (current_address % align_to)) % align_to
        return padding, current_address + padding

    # DATA → .BYTE, .WORD, .FILL, .ASCII, .ASCIZ
    if parsed.get("data") is not None:
        max_val = max(parsed["data"]) if parsed["data"] else 0
        return len(parsed["data"]) * (2 if max_val > 0xFF else 1), current_address

    # Direktifse → (örneğin .ORG, .END, .DEF, .REF)
    if parsed.get("opcode") in [".ORG", ".END", ".DEF", ".REF"]:
        return 0, current_address
    
    if parsed.get("opcode") in ["CLR", "INC", "DEC", "TST"]:
        return 2, current_address + 2

    # Literal Pool → 2 + 2
    if parsed.get("use_literal_pool"):
        return 4, current_address

    # Immediate ama const_generator değil → 2 + 2
    if parsed.get("is_immediate") and not parsed.get("use_const_generator"):
        return 4, current_address
        # JMP LABEL → JMP bir etiket içeriyorsa, MOV &LABEL, PC yapılacak → 4 byte
    
    if parsed.get("opcode") == "CMP":
        return 2, current_address + 2

    if parsed.get("opcode") == "JMP":
        op1 = parsed.get("op1", "")
        if not re.match(r'^(@?R\d\+?)$', op1):  # Eğer bir register değilse
            return 4, (current_address + 4 if current_address is not None else None)
   
    if parsed.get("opcode") == "MOV" and parsed.get("is_immediate"):
        return 4, current_address + 4
 
    # Normal instruction
    return 2, current_address+2

def pass1(program):
    global current_section
    symbol_table = {}
    literal_table = {}
    addresses = []

    # Reset section addresses
    for sect in section_info:
        section_info[sect]["current_address"] = section_info[sect]["start_address"]

    current_section_name = ".text"
    current_address = section_info[current_section_name]["current_address"]

    for line in program:
        upper_line = line.strip().upper()
        meta_directives = (".DEF", ".EQU", ".MACRO", ".ENDM", ".IFDEF", ".IFNDEF", ".ELSE", ".ENDIF", ".INCLUDE")
        if any(upper_line.startswith(dir) for dir in meta_directives):
            print(f"[PASS1] {line.strip()} -> META DIRECTIVE, adres atlaniyor")
            continue

        current_address = section_info[current_section_name]["current_address"]
        print(f"\n[LINE] {line.strip()} — CURRENT SECTION: {current_section_name}, ADDR: {current_address:04X}")

        parsed, _ = parse_line(line, symbol_table)
        if not parsed:
            continue

        # .ORG işle
        if parsed.get("directive") == "org":
            if parsed["operands"]:
                new_address = int(parsed["operands"][0], 0)

                # Tüm işlemleri tek bir değişkenle yap
                section_info[current_section]["current_address"] = new_address

                # Eğer başlangıç adresi önceden tanımlanmadıysa, ayarla
                if "start_address" not in section_info[current_section] or section_info[current_section]["start_address"] == 0:
                    section_info[current_section]["start_address"] = new_address

                current_address = new_address
                print(f"[ORG] Section '{current_section}' adresi {new_address:04X} olarak ayarlandi")
            continue


        # Section değiştir
        if parsed.get("directive") == "section":
            sect_name = parsed.get("section")
            if sect_name in section_info:
                current_section = sect_name
                current_address = section_info[current_section]["current_address"]
            else:
                raise ValueError(f"[PASS2] Section not found: {sect_name}")
            continue


        # Label varsa
        if parsed.get("label"):
            symbol_table[parsed["label"]] = current_address
            print(f"[LABEL] {parsed['label']} defined at {current_address:04X}")

        # CALL: 4 bayt
        if parsed.get("opcode") == "CALL":
            addresses.append((current_section_name, current_address))
            addresses.append((current_section_name, current_address + 2))
            current_address += 4
            section_info[current_section_name]["current_address"] = current_address
            continue

        # MOV #imm özel işlem
        if parsed.get("opcode") == "MOV" and parsed.get("is_immediate"):
            try:
                imm = int(parsed["immediate_value"])
                parsed["use_const_generator"] = imm in msp430_literal_constants or 0 <= imm <= 255
            except:
                parsed["use_const_generator"] = False

            if parsed["use_const_generator"]:
                addresses.append((current_section_name, current_address))
                current_address += 2
            else:
                addresses.append((current_section_name, current_address))
                addresses.append((current_section_name, current_address + 2))
                current_address += 4

            section_info[current_section_name]["current_address"] = current_address
            continue

        # Literal pool ekle
        if parsed.get("use_literal_pool"):
            val = parsed["immediate_value"]
            if val not in literal_table:
                literal_table[val] = None

        # Veri tanımları
        if parsed.get("data") is not None:
            for dval in parsed["data"]:
                addresses.append((current_section_name, current_address))
                if dval > 0xFF:
                    current_address += 2
                else:
                    current_address += 1
            section_info[current_section_name]["current_address"] = current_address
            continue

        # .SPACE işleme
        if parsed.get("opcode") == ".SPACE":
            size, new_addr = instruction_length(parsed, current_address)
            for i in range(size):
                addresses.append((current_section_name, current_address + i))
            section_info[current_section_name]["current_address"] = new_addr
            continue

        # .ALIGN işleme
        if parsed.get("opcode") == ".ALIGN":
            size, new_addr = instruction_length(parsed, current_address)
            section_info[current_section_name]["current_address"] = new_addr
            continue

        # Pseudo-instructionlar (tek kelimelik komutlar)
        if parsed.get("opcode") in ["RET", "NOP", "PUSH", "CLR", "INC", "DEC", "TST"]:
            addresses.append((current_section_name, current_address))
            current_address += 2
            section_info[current_section_name]["current_address"] = current_address
            continue

        # Diğer komutlar
        if parsed.get("opcode"):
            size, _ = instruction_length(parsed, current_address)
            addresses.append((current_section_name, current_address))
            current_address += size
            section_info[current_section_name]["current_address"] = current_address

    # LITERAL POOL EKLE
    if literal_table and ".text" in section_info:
        for val in literal_table:
            literal_table[val] = (".text", section_info[".text"]["current_address"])
            section_info[".text"]["current_address"] += 2

    addresses.sort(key=lambda x: (x[0], x[1]))

    print("\n--- ADDRESS LIST ---")
    for section_name, addr in addresses:
        print(f"{addr:04X} in section {section_name}")

    return symbol_table, addresses, literal_table

def pass2(program, symbol_table, addresses, literal_table=None):
    machine_code = []
    obj_lines = []  # Add this line
    addr_iter = iter(sorted(addresses, key=lambda x: (x[0], x[1])))
    used_addresses = set()
    processed_lines = set()
    current_section = ".text"
    current_address = section_info[current_section]["current_address"]

    for line in program:
        if line in processed_lines:
            continue
        processed_lines.add(line)
        if line.strip().upper().startswith(".DUMP"):
                match = re.search(r'\.DUMP\s+"([^"]+)"', line, re.IGNORECASE)
                if match:
                    dump_virtual_memory(match.group(1))
                    continue

        parsed, _ = parse_line(line, symbol_table)
        if not parsed:
            continue

        # SECTION değiştirme
        if parsed.get("directive") == "section":
            sect_name = parsed.get("section")
            if sect_name in section_info:
                current_section = sect_name            
                current_address = section_info[current_section]["current_address"]
                print(f"[SECTION] Section degisti: {current_section}, yeni current_address: {current_address:04X}")
            else:
                raise ValueError(f"[PASS2] Section bulunamadi: {sect_name}")
            continue


        # .ORG işleme 
        if parsed.get("directive") == "org":
            new_address = int(parsed["operands"][0], 0)
            section_info[current_section]["current_address"] = new_address
            current_address = new_address
            continue

        opcode = parsed.get("opcode")
        op1 = parsed.get("op1")
        op2 = parsed.get("op2")
        def write_word(address, value, section_name=None):
            if section_name is None:
                section_name = current_section
            if address in used_addresses or (address + 1) in used_addresses:
                print(f"[PASS2 WARNING] Word address {address:04X} (or {address + 1:04X}) already used!")
                return False
            used_addresses.add(address)
            used_addresses.add(address + 1)
            machine_code.append((address, value, 2))  # size = 2

            # Section içeriğine ekle
            if section_name in section_info:
                section_info[section_name]["content"].append((address, value))

            # 🔧 SANAL BELLEĞE YAZ (little endian, ve section bilgisiyle birlikte tuple olarak!)
            virtual_memory[address] = (value & 0xFF, section_name)
            virtual_memory[address + 1] = ((value >> 8) & 0xFF, section_name)

            return True

        def write_byte(address, value, section_name=None):
            if section_name is None:
                section_name = current_section
            if address in used_addresses:
                print(f"[PASS2 WARNING] Byte address {address:04X} already used!")
                return False
            used_addresses.add(address)
            machine_code.append((address, value & 0xFF, 1))  # 3. parametre: size = 1

            # Section içeriğine ekle
            if section_name in section_info:
                section_info[section_name]["content"].append((address, value & 0xFF))

            #  SANAL BELLEĞE YAZ
            virtual_memory[address] = (value & 0xFF, section_name)

            return True

        # Veri tanımı
        if parsed.get("data") is not None:
            for val in parsed["data"]:
                if val <= 0xFF:
                    write_byte(current_address, val, current_section)
                    current_address += 1
                else:
                    write_word(current_address, val, current_section)
                    current_address += 2
            section_info[current_section]["current_address"] = current_address
            continue

        # .SPACE
        if parsed.get("opcode") == ".SPACE":
            size = int(parsed.get("op1"))
            for i in range(size):
                write_byte(current_address + i, 0, current_section)
            section_info[current_section]["current_address"] = current_address + size
            continue

                
        if parsed.get("opcode") == ".BYTE":
            byte_values = parsed.get("data", [])
            for val in byte_values:
                write_byte(current_address, val, current_section)
                current_address += 1
            section_info[current_section]["current_address"] = current_address
            continue

        if parsed.get("opcode") == ".WORD":
            word_values = parsed.get("data", [])
            for val in word_values:
                write_word(current_address, val, current_section)
                current_address += 2
            section_info[current_section]["current_address"] = current_address
            continue

        if parsed.get("opcode") in [".ASCII", ".ASCIZ"]:
            text = parsed.get("ascii", "")
            for char in text:
                ascii_val = ord(char)
                write_byte(current_address, ascii_val, current_section)
                obj_lines.append(f":01{current_address:04X}00{ascii_val:02X}")
                current_address += 1

            if parsed.get("opcode") == ".ASCIZ":
                write_byte(current_address, 0, current_section)
                obj_lines.append(f":01{current_address:04X}0000")
                current_address += 1

            section_info[current_section]["current_address"] = current_address
            continue

        # .ALIGN sadece atlanıyor
        if opcode == ".ALIGN":
            continue

        # Pseudo
        # --- PSEUDO INSTRUCTION BLOK (FİXLENMİŞ) ----------------
        if opcode == "RET":
            write_word(current_address, 0x4130, current_section)
            current_address += 2
            section_info[current_section]["current_address"] = current_address
            continue

        if opcode == "NOP":
            write_word(current_address, 0x0000, current_section)
            current_address += 2
            section_info[current_section]["current_address"] = current_address
            continue

        if opcode == "CALL":
            write_word(current_address, opcode_table["CALL"], current_section)
            write_word(current_address + 2,
                    symbol_table.get(op1, 0), current_section)
            current_address += 4
            section_info[current_section]["current_address"] = current_address
            continue

        if parsed.get("is_immediate") and not parsed.get("use_const_generator"):
            dst_reg, dst_as, _ = detect_addressing_mode(op2)
            hex_code = (opcode_table["MOV"]
                        | (3 << 8) | (3 << 6) | (dst_as << 4) | dst_reg)
            write_word(current_address,     hex_code,               current_section)
            write_word(current_address + 2, parsed["immediate_value"], current_section)
            current_address += 4
            section_info[current_section]["current_address"] = current_address
            continue

        # --- GENERIC INSTRUCTION -------------------------------
        if opcode in opcode_table:
            src_reg, src_as, _ = detect_addressing_mode(op1)
            dst_reg, dst_as, _ = detect_addressing_mode(op2)
            hex_code = (opcode_table[opcode]
                        | (src_reg << 8) | (src_as << 6)
                        | (dst_as << 4) | dst_reg)
            write_word(current_address, hex_code, current_section)
            current_address += 2
            section_info[current_section]["current_address"] = current_address
            continue
        # Literal yaz
        if literal_table:
            for val, (sect, lit_addr) in literal_table.items():
                if lit_addr not in used_addresses:
                    write_word(lit_addr, val, sect)   # <-- 3. parametre eklendi


    with open("output.hex", "w") as hex_file:
        for addr, val, size in sorted(machine_code, key=lambda x: x[0]):
            if size == 1:
                hex_file.write(f"{addr:04X}: {val:02X}\n")
            elif size == 2:
                hex_file.write(f"{addr:04X}: {val:04X}\n")


    return machine_code

def read_assembly_output(filename):
    instructions = []
    with open(filename, "r") as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) >= 2:
                address = int(parts[0].strip(':'), 16)
                machine_code = parts[1]
                instructions.append((address, machine_code))
    return instructions


def write_object_file(program_name, instructions):
    def checksum(byte_list):
        return ((~sum(byte_list) + 1) & 0xFF)

    # Adresleri sırala 
    instructions.sort()

    with open(f"{program_name}.obj", "w") as f:
        current_block = []
        block_start_addr = None

        for i, (addr, word) in enumerate(instructions):
            word = int(word, 16) if isinstance(word, str) else word
            lo = word & 0xFF
            hi = (word >> 8) & 0xFF

            if not current_block:
                block_start_addr = addr
                current_block.append((addr, lo, hi))
                continue

            last_addr = current_block[-1][0]
            expected_next_addr = last_addr + 2  # kelime → 2 byte

            if addr == expected_next_addr and len(current_block) < 8:  # max 16 byte = 8 kelime
                current_block.append((addr, lo, hi))
            else:
                #  Mevcut bloğu yaz
                byte_data = []
                for _, lo_, hi_ in current_block:
                    byte_data.extend([lo_, hi_])
                count = len(byte_data)
                addr_hi = (block_start_addr >> 8) & 0xFF
                addr_lo = block_start_addr & 0xFF
                record = [count, addr_hi, addr_lo, 0x00] + byte_data
                chk = checksum(record)
                f.write(f":{count:02X}{block_start_addr:04X}00{''.join(f'{b:02X}' for b in byte_data)}{chk:02X}\n")

                # Yeni bloğu başlat
                block_start_addr = addr
                current_block = [(addr, lo, hi)]

        #  Kalan son blok
        if current_block:
            byte_data = []
            for _, lo_, hi_ in current_block:
                byte_data.extend([lo_, hi_])
            count = len(byte_data)
            addr_hi = (block_start_addr >> 8) & 0xFF
            addr_lo = block_start_addr & 0xFF
            record = [count, addr_hi, addr_lo, 0x00] + byte_data
            chk = checksum(record)
            f.write(f":{count:02X}{block_start_addr:04X}00{''.join(f'{b:02X}' for b in byte_data)}{chk:02X}\n")

        # EOF kaydı
        f.write(":00000001FF\n")

def write_section_object_files_hex_format(output_dir="."):
    def checksum(byte_list):
        return ((~sum(byte_list) + 1) & 0xFF)

    os.makedirs(output_dir, exist_ok=True)

    for sect_name, info in section_info.items():
        contents = info.get("content", [])
        if not contents:
            continue

        contents.sort()
        filename = os.path.join(output_dir, f"{sect_name[1:]}.obj")
        with open(filename, "w") as f:
            f.write(f"; Section: {sect_name}\n")

            current_block = []          # [(addr, [bytes]), …]
            block_start_addr = None

            for addr, val in contents:
                # ───── NEW: decide how many bytes this “val” really has ─────
                if val <= 0xFF:                       # 1-byte literal / .BYTE / .ASCII
                    data_bytes = [val]
                else:                                 # 16-bit word (instruction / .WORD)
                    data_bytes = [val & 0xFF, (val >> 8) & 0xFF]

                if not current_block:
                    block_start_addr = addr
                    current_block.append((addr, data_bytes))
                    continue

                last_addr  = current_block[-1][0]
                last_size  = len(current_block[-1][1])
                expected_next_addr = last_addr + last_size

                # keep the block ≤ 16 bytes
                block_len = sum(len(b) for _, b in current_block)
                if addr == expected_next_addr and (block_len + len(data_bytes)) <= 16:
                    current_block.append((addr, data_bytes))
                else:
                    # ---------- flush existing block ----------
                    byte_data = []
                    for _, b in current_block:
                        byte_data.extend(b)
                    count = len(byte_data)
                    record = [count,
                              (block_start_addr >> 8) & 0xFF,
                              block_start_addr & 0xFF,
                              0x00] + byte_data
                    f.write(f":{count:02X}{block_start_addr:04X}00"
                            f"{''.join(f'{b:02X}' for b in byte_data)}"
                            f"{checksum(record):02X}\n")

                    # ---------- start a new block ----------
                    block_start_addr = addr
                    current_block = [(addr, data_bytes)]

            # ---------- flush the very last block ----------
            if current_block:
                byte_data = []
                for _, b in current_block:
                    byte_data.extend(b)
                count = len(byte_data)
                record = [count,
                        (block_start_addr >> 8) & 0xFF,
                        block_start_addr & 0xFF,
                        0x00] + byte_data
                f.write(f":{count:02X}{block_start_addr:04X}00"
                        f"{''.join(f'{b:02X}' for b in byte_data)}"
                        f"{checksum(record):02X}\n")

            f.write(":00000001FF\n")      # EOF


def assemble_program(input_file="main.asm"):
    
    with open(input_file, 'r') as f:
        program = f.readlines()
    
    program = process_includes(program, base_path=os.path.dirname(input_file))
    program = preprocess_defines(program)
    print("DEFINE TABLE AT ENTRY:", define_table) 
    program = process_conditionals(program)        # ← .IFDEF buraya kadar ENABLE_OUTPUT görmeli
    program = preprocess_macros(program)           # ← Son olarak makrolar açılır

    print("\n--- PROGRAM LINES ---")
    for i, line in enumerate(program):
        print(f"{i:02}: {line.strip()}")

    
    print("SECTION INFO:")
    for k, v in section_info.items():
        print(f"{k} start={v['start_address']:04X}, current={v['current_address']:04X}, content count={len(v['content'])}")
        
    print("\n--- SECTION INFO ---")
    for name, info in section_info.items():
        print(f"{name}: start=0x{info['start_address']:04X}, end=0x{info['current_address']:04X}")

    # 1. geçiş: etiket, adres, literal tabloları oluştur
    symbol_table, addresses, literal_table = pass1(program)

    # 2. geçiş: makine kodlarını üret ve hex'e yaz
    machine_code = pass2(program, symbol_table, addresses, literal_table)

    # output.hex'ten oku ve obj dosyasına yaz
    instructions = read_assembly_output("output.hex")
    
    write_object_file("MSP430", instructions)
    write_section_object_files_hex_format("output_objs")  # ensure this runs!

    print("Assembly successful. Files: output.hex, MSP430.obj")

def linker(input_dir="output_objs", output_file="linked_output.hex"):
    """
    Links multiple object files generated by the assembler.
    Supports .DEF and .REF symbol resolution and basic relocation.
    """
    symbol_table = {}
    relocation_entries = []
    memory_image = {}

    # Pass 1: Collect all exported symbols
    for obj_file in glob.glob(os.path.join(input_dir, "*.obj")):
        with open(obj_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith(";"):
                    # Parse section or symbol export info
                    if "EXPORT:" in line:
                        parts = line.strip().split()
                        if len(parts) == 3:
                            symbol = parts[2]
                            addr = int(parts[1], 16)
                            symbol_table[symbol] = addr
                    continue

    # Pass 2: Read object data and apply relocations
    for obj_file in glob.glob(os.path.join(input_dir, "*.obj")):
        with open(obj_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                if not line.startswith(":"):
                    continue
                byte_count = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data = line[9:9 + byte_count * 2]

                for i in range(0, len(data), 4):
                    word_hex = data[i:i+4]
                    word = int(word_hex, 16)
                    memory_image[address] = word
                    address += 2

    # Generate final linked HEX file
    with open(output_file, "w") as f:
        sorted_addresses = sorted(memory_image.keys())
        for addr in sorted_addresses:
            word = memory_image[addr]
            f.write(f"{addr:04X}: {word:04X}\n")
    print(f"[LINKER] Linked output written to: {output_file}")

def dump_virtual_memory(filename="virtual_memory.txt"):
    try:
        with open(filename, "w") as f:
            for addr in sorted(virtual_memory.keys()):
                val, sect = virtual_memory[addr]
                sect_display = sect if sect else "UNKNOWN"
                line = f"{addr:04X}: {val:02X}    ; section = {sect_display}"
                print(line)
                f.write(line + "\n")

        print(f"[DUMP] Virtual memory dumped to '{filename}' successfully.")

    except Exception as e:
        print(f"[ERROR] Failed to dump virtual memory: {e}")


    except Exception as e:
        print(f"[ERROR] Failed to dump virtual memory: {e}")


def generate_memview(output_file="memview.txt"):
    try:
        with open(output_file, "w") as f:
            for addr in sorted(virtual_memory.keys()):
                val, section = virtual_memory[addr]
                if section is None:
                    section = "UNKNOWN"
                line = f"{addr:04X}: {val:04X}    ; section = {section}"
                f.write(line + "\n")
                print(line)
        print(f"[MEMVIEW] Memory view saved to '{output_file}'")
    except Exception as e:
        print(f"[MEMVIEW ERROR] Failed to generate memview: {e}")


def interactive_memory_tool():
    print("\n Sanal Bellek Etkilesim Modu -.peek <addr> | .poke <addr> <val> | .exit")

    while True:
        command = input(">> ").strip()
        if not command:
            continue

        if command.lower() in [".exit", "exit", "quit"]:
            print("Çikiliyor...")
            break

        if command.lower().startswith(".peek"):
            try:
                _, addr_str = command.split()
                addr_str = addr_str.upper()
                val = virtual_memory.get(addr_str, None)
                if val is not None:
                    print(f"[.peek] {addr_str} → {val:04X}")
                else:
                    print(f"[.peek] {addr_str} adresi bulunamadi.")
            except:
                print("Kullanim: .peek <adres>")

        elif command.lower().startswith(".poke"):
            try:
                _, addr_str, val_str = command.split()
                addr_str = addr_str.upper()
                val = int(val_str, 0)
                virtual_memory[addr_str] = val
                print(f"[.poke] {addr_str} ← {val:04X}")
            except:
                print("Kullanim: .poke <adres> <değer>")

        else:
            print("Bilinmeyen komut. Kullanim: .peek <adres> | .poke <adres> <değer> | .exit")

def get_section_name(addr):
    """
    Hangi section’ın sınırları içinde olduğuna bakarak
    adresin ait olduğu section adını döndürür.
    """
    for name, info in section_info.items():
        start = info["start_address"]
        end   = info["current_address"] - 1   # dâhilî son adres
        if start <= addr <= end:
            return name
    return "UNKNOWN"

def loader(input_file="linked_output.hex"):
    """
    Loads a memory map file with format like '0200: 48' into virtual memory.
    """
    global virtual_memory
    virtual_memory.clear()

    try:
        with open(input_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue  # skip empty lines or invalid lines

                try:
                    # Example line: "0200: 48" or "C000: 43C4"
                    address_str, value_str = line.split(":")
                    address = int(address_str.strip(), 16)
                    value_str = value_str.strip()

                    # Decide if this is byte (2 hex chars) or word (4 hex chars)
                    if len(value_str) == 2:
                        # single byte
                        value = int(value_str, 16)
                        virtual_memory[address] = value
                    elif len(value_str) == 4:
                        # word (split into two bytes)
                        value = int(value_str, 16)
                        virtual_memory[address] = value & 0xFF         # low byte
                        virtual_memory[address + 1] = (value >> 8) & 0xFF  # high byte
                    else:
                        print(f"[LOADER] Invalid data length: {line}")
                except Exception as e:
                    print(f"[LOADER] Error parsing line: {line} -> {e}")
    except Exception as e:
        print(f"[LOADER] Failed to load file '{input_file}': {e}")
        return

    print(f"[LOADER] Loaded memory from '{input_file}' into virtual_memory.")

if __name__ == "__main__":
    # Combine both files for testing
    with open("main.asm") as f1, open("constant.asm") as f2:
        combined = f1.readlines() + f2.readlines()
    with open("combined.asm", "w") as fout:
        fout.writelines(combined)

    assemble_program("combined.asm")
    linker()
    loader()