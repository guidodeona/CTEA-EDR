
def detect_suspicious_connections(connections, rules):
    alerts = []
    suspicious_ports = rules.get('network', {}).get('suspicious_ports', [])

    for conn in connections:
        # Check remote port if connection is established
        if conn.status == 'ESTABLISHED' and conn.raddr:
            remote_port = conn.raddr.port
            if remote_port in suspicious_ports:
                alerts.append({
                    "type": "NETWORK",
                    "pid": conn.pid,
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "risk": 50,
                    "description": f"Connection to suspicious port {remote_port}"
                })
                
    return alerts

