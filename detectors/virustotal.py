
import hashlib
import requests
import os
import time

def get_file_hash(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return None

def check_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key,
        "content-type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
            return result
        elif response.status_code == 404:
            return {"status": "not_found", "message": "File not found in VirusTotal database"}
        elif response.status_code == 401:
            return {"status": "error", "message": "Invalid API Key"}
        else:
            return {"status": "error", "message": f"API Error: {response.status_code}"}
            
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan_processes_with_virustotal(processes, api_key, limit=5):
    """
    Scans running processes against VirusTotal.
    Due to API rate limits (4/min on free tier), we limit scans to a few high-risk items 
    or just a sample.
    """
    alerts = []
    scanned_count = 0
    
    print("\n[*] Scanning processes with VirusTotal (Limited to top 5)...")
    
    for p in processes:
        if scanned_count >= limit:
            break
            
        exe_path = p.get('exe')
        if not exe_path or not os.path.exists(exe_path):
            continue
            
        # Skip common trusted system paths to focus on user/temp/unknown locations
        # This is a naive heuristic to execute fewer API calls
        if "Windows\\System32" in exe_path or "Program Files" in exe_path:
             # Uncomment to skip these: continue 
             pass

        file_hash = get_file_hash(exe_path)
        if not file_hash:
            continue
            
        result = check_virustotal(file_hash, api_key)
        
        if "malicious" in result and (result['malicious'] > 0 or result['suspicious'] > 0):
            alerts.append({
                "type": "VIRUSTOTAL",
                "pid": p['pid'],
                "name": p['name'],
                "hash": file_hash,
                "vt_stats": result,
                "risk": 100 if result['malicious'] > 0 else 50
            })
        
        scanned_count += 1
        # Respect rate limit roughly (15s delay between requests if doing many)
        # But for 'limit=5', we might hit it immediately. Let's add a small sleep.
        time.sleep(15) 

    return alerts
