
import winreg
import logging

class PersistenceMonitor:
    
    def __init__(self, monitored_keys=None):
        self.monitored_keys = monitored_keys or [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        self.snapshot = {}
        self.take_snapshot() # Crear estado inicial

    def take_snapshot(self):
        """Lee todas las llaves y guarda su estado actual en memoria."""
        for subkey in self.monitored_keys:
            try:
                # Intentar leer HKEY_CURRENT_USER
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
                    values = {}
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            values[name] = value
                            i += 1
                        except OSError:
                            break
                    self.snapshot[("HKCU", subkey)] = values
            except FileNotFoundError:
                pass
            except PermissionError:
                logging.warning(f"[PERSISTENCE] Access denied to HKCU\\{subkey}")

    def check_changes(self):
        """Compara el estado actual con el snapshot anterior y devuelve alertas."""
        alerts = []
        current_state = {}

        # 1. Leer estado actual
        for subkey in self.monitored_keys:
            current_values = {}
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            current_values[name] = value
                            i += 1
                        except OSError:
                            break
            except Exception: 
                continue
            
            key_id = ("HKCU", subkey)
            previous_values = self.snapshot.get(key_id, {})

            # 2. Detectar nuevas entradas (Persistencia agregada)
            for name, value in current_values.items():
                if name not in previous_values:
                    alerts.append({
                        "type": "PERSISTENCE",
                        "risk": 90,
                        "name": f"New Startup Item: {name}",
                        "details": f"Path: {value} | Key: {subkey}"
                    })
                elif previous_values[name] != value:
                    alerts.append({
                        "type": "PERSISTENCE_MODIFIED",
                        "risk": 85,
                        "name": f"Startup Item Changed: {name}",
                        "details": f"Old: {previous_values[name]} -> New: {value}"
                    })

            # Actualizar snapshot
            self.snapshot[key_id] = current_values
            
        return alerts
