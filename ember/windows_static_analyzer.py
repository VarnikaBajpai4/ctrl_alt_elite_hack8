#!/usr/bin/python3

import os
import re
import sys
import json
import hashlib
import binascii
import subprocess
from pathlib import Path
import pefile as pf
import yara
import logging

logger = logging.getLogger(__name__)

class WindowsExecutableAnalyzer:
    def __init__(self, target_file):
        self.target_file = target_file
        self.executable_buffer = open(self.target_file, "rb").read()
        self.all_strings = self.extract_strings()
        self.binaryfile = pf.PE(target_file)
        self.yara_rules = self.load_yara_rules()
        
        # API categories
        self.api_categories = {
            "Registry": ["RegOpenKey", "RegCreateKey", "RegSetValue", "RegQueryValue", "RegDeleteKey", "RegDeleteValue"],
            "File": ["CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile", "MoveFile", "FindFirstFile", "FindNextFile"],
            "Networking/Web": ["socket", "connect", "send", "recv", "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"],
            "Keyboard/Keylogging": ["GetAsyncKeyState", "GetKeyboardState", "SetWindowsHookEx"],
            "Process": ["CreateProcess", "OpenProcess", "TerminateProcess", "CreateRemoteThread", "WriteProcessMemory"],
            "Memory Management": ["VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc", "HeapFree"],
            "Dll/Resource Handling": ["LoadLibrary", "GetProcAddress", "FreeLibrary", "LoadResource", "LockResource"],
            "Evasion/Bypassing": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString", "GetTickCount"],
            "System/Persistence": ["CreateService", "StartService", "OpenService", "ChangeServiceConfig"],
            "COMObject": ["CoCreateInstance", "CoInitialize", "CoUninitialize"],
            "Cryptography": ["CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptEncrypt", "CryptDecrypt"],
            "Information Gathering": ["GetSystemInfo", "GetComputerName", "GetUserName", "GetSystemDirectory", "GetWindowsDirectory"],
            "Other/Unknown": []
        }

    def load_yara_rules(self):
        """Load YARA rules from the YaraRules_Windows directory"""
        script_dir = Path(__file__).parent
        rules_dir = script_dir / "Systems" / "Windows" / "YaraRules_Windows"
        
        if not rules_dir.exists():
            logger.error(f"YARA rules directory not found: {rules_dir}")
            return None
        
        try:
            rules = {}
            for rule_file in rules_dir.glob("*.yar*"):
                try:
                    rules[rule_file.stem] = yara.compile(str(rule_file))
                    logger.debug(f"Loaded YARA rule: {rule_file.stem}")
                except yara.SyntaxError as e:
                    logger.warning(f"Failed to compile YARA rule {rule_file.stem}: {str(e)}")
                    continue
            return rules
        except Exception as e:
            logger.error(f"Error loading YARA rules: {str(e)}")
            return None

    def scan_with_yara(self):
        """Scan the file with YARA rules"""
        if not self.yara_rules:
            logger.warning("No YARA rules loaded")
            return []
        
        matches = []
        for rule_name, rule in self.yara_rules.items():
            try:
                rule_matches = rule.match(data=self.executable_buffer)
                if rule_matches:
                    for match in rule_matches:
                        severity = "Medium"
                        if any(x in rule_name.lower() for x in ['apt', 'malw', 'stealer', 'rat']):
                            severity = "High"
                        elif any(x in rule_name.lower() for x in ['toolkit', 'miner']):
                            severity = "Medium"
                        else:
                            severity = "Low"
                        
                        matches.append({
                            "rule_name": rule_name,
                            "description": match.meta.get("description", ""),
                            "severity": severity,
                            "category": match.meta.get("category", "unknown")
                        })
                        logger.debug(f"YARA match found: {rule_name} - {severity}")
            except Exception as e:
                logger.warning(f"Error scanning with rule {rule_name}: {str(e)}")
                continue
        
        return matches

    def extract_strings(self):
        """Extract strings from the executable"""
        strings_param = "-a" if sys.platform == "win32" else "--all"
        subprocess.run(f"strings {strings_param} \"{self.target_file}\" > temp.txt", 
                      shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        return open("temp.txt", "r").read().split("\n")

    def calculate_hashes(self):
        """Calculate file hashes"""
        hashes = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256()
        }
        
        with open(self.target_file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        
        return {k: v.hexdigest() for k, v in hashes.items()}

    def analyze_imports_exports(self):
        """Analyze imports and exports"""
        imports_exports = {
            "imports": [],
            "exports": [],
            "dlls": [],
            "categorized_imports": {category: [] for category in self.api_categories.keys()}
        }
        
        # Get imports
        if hasattr(self.binaryfile, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.binaryfile.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii")
                imports_exports["dlls"].append(dll_name)
                
                for imp in entry.imports:
                    if imp.name:
                        import_name = imp.name.decode("ascii")
                        imports_exports["imports"].append({
                            "name": import_name,
                            "address": hex(self.binaryfile.OPTIONAL_HEADER.ImageBase + imp.address),
                            "dll": dll_name
                        })
                        
                        # Categorize imports
                        for category, apis in self.api_categories.items():
                            if any(api in import_name for api in apis):
                                imports_exports["categorized_imports"][category].append(import_name)
                                break
        
        # Get exports
        if hasattr(self.binaryfile, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.binaryfile.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    imports_exports["exports"].append({
                        "name": exp.name.decode('utf-8'),
                        "address": hex(self.binaryfile.OPTIONAL_HEADER.ImageBase + exp.address)
                    })
        
        return imports_exports

    def analyze_sections(self):
        """Analyze PE sections"""
        sections = []
        for section in self.binaryfile.sections:
            try:
                entropy = section.get_entropy()
                sections.append({
                    "name": str(section.Name.decode().rstrip('\x00')),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "virtual_address": hex(section.VirtualAddress),
                    "raw_size": hex(section.SizeOfRawData),
                    "entropy": entropy,
                    "is_obfuscated": entropy >= 7
                })
            except:
                continue
        return sections

    def find_embedded_pe(self):
        """Search for embedded PE files"""
        mz_header = "4D5A9000"
        matches = re.finditer(binascii.unhexlify(mz_header), self.executable_buffer)
        valid_offsets = [pos.start() for pos in matches if pos.start() != 0]
        return valid_offsets

    def analyze_strings(self):
        """Analyze interesting strings"""
        patterns = [
            r'\b[a-zA-Z0-9_\-\\/:]+\.pdb', r'\b[a-zA-Z0-9_\-\\/:]+\.vbs', 
            r'\b[a-zA-Z0-9_\-\\/:]+\.vba', r'\b[a-zA-Z0-9_\-\\/:]+\.vbe', 
            r'\b[a-zA-Z0-9_\-\\/:]+\.exe', r'\b[a-zA-Z0-9_\-\\/:]+\.ps1',
            r'\b[a-zA-Z0-9_\-\\/:]+\.dll', r'\b[a-zA-Z0-9_\-\\/:]+\.bat',
            r'\b[a-zA-Z0-9_\-\\/:]+\.cmd', r'\b[a-zA-Z0-9_\-\\/:]+\.tmp',
            r'\b[a-zA-Z0-9_\-\\/:]+\.dmp', r'\b[a-zA-Z0-9_\-\\/:]+\.cfg',
            r'\b[a-zA-Z0-9_\-\\/:]+\.lnk', r'\b[a-zA-Z0-9_\-\\/:]+\.config',
            r'\b[a-zA-Z0-9_\-\\/:]+\.7z', r'\b[a-zA-Z0-9_\-\\/:]+\.docx',
            r"SeLockMemoryPrivilege", r"SeShutdownPrivilege",
            r"SeChangeNotifyPrivilege", r"SeUndockPrivilege",
            r"SeIncreaseWorkingSetPrivilege", r"SeTimeZonePrivilege",
            r"Select \* from \w+", r"VirtualBox", r"vmware", r"syscall\.[a-zA-Z0-9]+"
        ]

        found_strings = set()
        for pattern in patterns:
            matches = re.findall(pattern, str(self.all_strings), re.IGNORECASE)
            for match in matches:
                if match not in found_strings:
                    found_strings.add(match)
        
        return list(found_strings)

    def analyze_registry_keys(self):
        """Analyze registry key references"""
        reg_patterns = [
            r"SOFTWARE\\[A-Za-z0-9_\\/\\\s]*",
            r"HKCU_[A-Za-z0-9_\\/\\\s]*",
            r"HKLM_[A-Za-z0-9_\\/\\\s]*",
            r"SYSTEM\\[A-Za-z0-9_\\/\\\s]*"
        ]
        
        found_keys = set()
        for pattern in reg_patterns:
            matches = re.findall(pattern, str(self.all_strings), re.IGNORECASE)
            for match in matches:
                if len(match) > 10 and match not in found_keys:
                    found_keys.add(match)
        
        return list(found_keys)

    def analyze(self):
        """Run complete analysis"""
        logger.info("Starting Windows executable analysis")
        
        # Load YARA rules
        logger.info("Loading YARA rules...")
        self.yara_rules = self.load_yara_rules()
        if self.yara_rules:
            logger.info(f"Loaded {len(self.yara_rules)} YARA rules")
        else:
            logger.warning("Failed to load YARA rules")
        
        # Run YARA scan
        logger.info("Running YARA scan...")
        yara_matches = self.scan_with_yara()
        logger.info(f"Found {len(yara_matches)} YARA matches")
        
        result = {
            "filename": self.target_file,
            "hashes": self.calculate_hashes(),
            "imports_exports": self.analyze_imports_exports(),
            "sections": self.analyze_sections(),
            "embedded_pe_files": self.find_embedded_pe(),
            "interesting_strings": self.analyze_strings(),
            "registry_keys": self.analyze_registry_keys(),
            "yara_matches": yara_matches
        }
        
        # Save report in the same directory as the input file
        report_file = os.path.join(os.path.dirname(self.target_file), f"{os.path.basename(self.target_file)}_analysis_report.json")
        with open(report_file, "w") as f:
            json.dump(result, f, indent=4)
        
        logger.info("Analysis complete")
        return result

def main():
    # Hardcoded file path
    target_file = "bad.exe"  # Change this to your target file path
    
    if not os.path.exists(target_file):
        return {"error": f"File {target_file} not found!"}
    
    analyzer = WindowsExecutableAnalyzer(target_file)
    return analyzer.analyze()

if __name__ == "__main__":
    main()