import os
import json
import re
import pefile
from collections import defaultdict

def extract_pe_features(binary_path, features):
    try:
        pe = pefile.PE(binary_path)
        features['pe_num_sections'] = len(pe.sections)
        features['pe_timestamp'] = pe.FILE_HEADER.TimeDateStamp
        features['pe_image_base'] = pe.OPTIONAL_HEADER.ImageBase
        features['pe_entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            entropy = section.get_entropy()
            features[f'sec_entropy_{name}'] = round(entropy, 2)
            features[f'sec_size_{name}'] = section.SizeOfRawData

        # Extract full import map
        pe_imports = defaultdict(list)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        pe_imports[dll].append(imp.name.decode(errors='ignore'))

        # Add to features
        for dll, apis in pe_imports.items():
            features[f'import_{dll}'] = len(apis)
            features[f'import_apis_{dll}'] = apis

    except Exception as e:
        print(f"[!] PE parsing failed: {e}")

def extract_imports_from_config(json_path):
    with open(json_path, 'r') as f:
        config = json.load(f)
    
    retdec_imports = defaultdict(list)
    for func in config.get("functions", []):
        if func.get("fncType") == "imported":
            dll = func.get("libraryName", "UNKNOWN").upper()
            name = func.get("name")
            if dll and name:
                retdec_imports[dll].append(name)
    
    return dict(retdec_imports)

def extract_features(malware_dir):
    features = {}

    # Find files
    files = os.listdir(malware_dir)
    binary_file = next((f for f in files if f.endswith(".exe")), None)
    json_file = next((f for f in files if f.endswith(".config.json")), None)
    c_file = next((f for f in files if f.endswith(".c")), None)
    dsm_file = next((f for f in files if f.endswith(".dsm")), None)
    ll_file = next((f for f in files if f.endswith(".ll")), None)

    # 1. PE Features
    if binary_file:
        binary_path = os.path.join(malware_dir, binary_file)
        extract_pe_features(binary_path, features)

    # 2. RetDec config.json
    if json_file:
        json_path = os.path.join(malware_dir, json_file)
        with open(json_path, "r") as f:
            config = json.load(f)
            features['architecture'] = config.get("architecture", "")
            features['file_format'] = config.get("fileFormat", "")
            features['endianness'] = config.get("endianness", "")
            features['file_class'] = config.get("fileClass", "")
            features['detected_language'] = config.get("detectedLanguage", "")

        # Extract full imported functions from config.json
        retdec_imports = extract_imports_from_config(json_path)
        features['retdec_imports'] = retdec_imports

    # 3. Decompiled C
    suspicious_keywords = ['CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory',
                           'GetProcAddress', 'LoadLibrary', 'system', 'socket', 'fork']
    if c_file:
        with open(os.path.join(malware_dir, c_file), "r", errors='ignore') as f:
            c_code = f.read()
            features['num_lines_c'] = len(c_code.splitlines())
            for keyword in suspicious_keywords:
                features[f'kw_{keyword}'] = keyword in c_code

    # 4. Disassembly (dsm)
    if dsm_file:
        with open(os.path.join(malware_dir, dsm_file), "r", errors='ignore') as f:
            dsm_code = f.read()
            opcodes = re.findall(r'^\s*[0-9a-f]+:\s+[0-9a-f]+\s+([a-z]+)', dsm_code, re.MULTILINE)
            opcode_counts = {}
            for op in opcodes:
                opcode_counts[op] = opcode_counts.get(op, 0) + 1
            for op, count in opcode_counts.items():
                features[f'op_{op}'] = count

    # 5. LLVM IR
    if ll_file:
        with open(os.path.join(malware_dir, ll_file), "r", errors='ignore') as f:
            ll_code = f.read()
            calls = re.findall(r'call.*?@([a-zA-Z_][a-zA-Z0-9_]*)', ll_code)
            for func in set(calls):
                features[f'll_call_{func}'] = calls.count(func)

    return features

if __name__ == "__main__":    
    malware_dir = "./output/testing"
    features = extract_features(malware_dir)

    with open(f'{malware_dir}/features.json', 'w') as json_file:
        json.dump(features, json_file, indent=4)
