import re,json, yaml
from pathlib import Path

patterns = json.load(open("scanner/patterns.json"))

allowlist_data = yaml.safe_load(open("SECHA/allowlist.yml"))
allowlist = allowlist_data.get("allow", allowlist_data.get("env_vars", []))

def scan_file(file_path):
    findings = []
    with open(file_path, "r") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        for name, pattern in patterns.items():
            if re.search(pattern, line):
                if any(a in line for a in allowlist):
                    continue
                findings.append({
                    "type" : name,
                    "line" : i + 1,
                    "match" : line.strip(),
                    "file" : str(file_path)
                })
    return findings

def scan_directory(target="SECHA"):
    results = []
    for file in Path(target).rglob("*.*"):
        if file.suffix in [".yml",".yaml",".json",".env",".sh",".py"]:
            results.extend(scan_file(file))
    return results

if __name__ == "__main__":
    output = scan_directory()
    print("scan done. finding: ")
    print(output)
    with open("output/results.json","w") as f:
        json.dump(output, f, indent=4)