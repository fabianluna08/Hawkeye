import yara
import os
import sys
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(SCRIPT_DIR, "rules")

def compile_rules():
    rule_files = {}
    if not os.path.exists(RULES_DIR):
        print(f"Error: Rules directory {RULES_DIR} not found.")
        return None

    for f in os.listdir(RULES_DIR):
        if f.endswith('.yar') or f.endswith('.yara'):
            rule_files[f] = os.path.join(RULES_DIR, f)
            
    if not rule_files:
        print("Error: No YARA rules found in rules directory.")
        return None

    try:
        return yara.compile(filepaths=rule_files)
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None

def scan_file(file_path, compiled_rules=None):
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "status": "error"}
        
    if compiled_rules is None:
        compiled_rules = compile_rules()
        if compiled_rules is None:
            return {"error": "Failed to compile rules.", "status": "error"}

    try:
        matches = compiled_rules.match(file_path)
        
        malicious_rules = []
        info_rules = []
        file_types = []
        
        for m in matches:
            meta = m.meta or {}
            rule_type = meta.get("rule_type", "malware") 
            
            if rule_type == "malware":
                malicious_rules.append(m.rule)
            elif rule_type == "info":
                info_rules.append(m.rule)
                if "file_type" in meta:
                    file_types.append(meta["file_type"])
                    
        status = "malicious" if malicious_rules else "clean"
        
        return {
            "status": status, 
            "malware_matches": malicious_rules,
            "info_matches": info_rules,
            "detected_file_types": file_types
        }
    except Exception as e:
        return {"error": f"Scanning failed: {e}", "status": "error"}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file path provided", "status": "error"}))
        sys.exit(1)
        
    res = scan_file(sys.argv[1])
    print(json.dumps(res))
