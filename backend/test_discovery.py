from app.scanners.param_discovery import discover_injectable_targets

candidates = discover_injectable_targets("http://scanme.nmap.org")
print(f"Found {len(candidates)} candidate(s):")
for c in candidates:
    print(" -", c)
