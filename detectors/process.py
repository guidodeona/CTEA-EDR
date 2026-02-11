import os
import psutil

def detect_suspicious_processes(processes, rules, os_type):
    alerts = []

    suspicious_paths = rules['process']['suspicious_paths'].get(os_type, [])
    behavioral_rules = rules['process'].get('behavioral', {}).get('suspicious_parents', [])

    for p in processes:
        try:
            exe = p.get('exe') or ""
            name = p.get('name') or ""
            pid = p.get('pid')
            
            # 1. Signature/Path Detection
            for path in suspicious_paths:
                if path.lower() in exe.lower():
                    alerts.append({
                        "type": "PROCESS_SIGNATURE",
                        "pid": pid,
                        "name": name,
                        "path": exe,
                        "risk": 80,
                        "description": f"Known malicious tool: {name}"
                    })

            # 2. Behavioral/Lineage Detection
            # We need to get the parent process name. 
            # Note: 'processes' input is a list of dicts. We might need to query psutil for parent if not provided,
            # or ideally, the Collector should provide parent info.
            # For now, let's query psutil directly for the parent since we have the PID.
            try:
                proc_obj = psutil.Process(pid)
                parent = proc_obj.parent()
                if parent:
                    parent_name = parent.name().lower()
                    child_name = name.lower()

                    for rule in behavioral_rules:
                        if rule['parent'] in parent_name and rule['child'] in child_name:
                             alerts.append({
                                "type": "BEHAVIORAL",
                                "pid": pid,
                                "name": name,
                                "parent": parent_name,
                                "risk": rule['risk'],
                                "description": f"Suspicious behavior: {parent_name} spawned {child_name}"
                            })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        except Exception as e:
            continue

    return alerts
