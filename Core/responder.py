import os
import platform
import psutil
import logging
import requests
import json
from datetime import datetime

class ThreatResponder:

    def __init__(self, webhook_url=None):
        self.os_type = platform.system().lower()
        self.webhook_url = webhook_url

    def respond(self, severity, events):
        if severity == "LOW":
            self._log_only(events)

        elif severity == "MEDIUM":
            self._alert(events)

        elif severity == "HIGH":
            self._alert(events)
            self._kill_processes(events)

    def _log_only(self, events):
        for e in events:
            logging.info(f"[LOW] {e}")

    def _alert(self, events):
        print("\n[!] ALERTA DE SEGURIDAD")
        for e in events:
            msg = f" - {e['type']} | {e.get('name')} | Risk: {e.get('risk', 0)}"
            print(msg)
            logging.warning(f"[ALERT] {e}")
            
            if self.webhook_url:
                self._send_notification(e)

    def _kill_processes(self, events):
        for e in events:
            # Kill Suspicious Process
            if e['type'] in ["PROCESS", "YARA_MATCH"]:
                pid = e.get('pid')
                if pid:
                    try:
                        p = psutil.Process(pid)
                        p.terminate()
                        logging.critical(
                            f"[KILLED] Process {e.get('name')} (PID {pid})"
                        )
                    except Exception as ex:
                        logging.error(f"Error killing PID {pid}: {ex}")

    def _send_notification(self, event):
        payload = {
            "username": "CTEA Security Alert",
            "embeds": [{
                "title": "🚨 Threat Detected!",
                "description": f"**Type:** {event['type']}\n**Name:** {event.get('name')}\n**Risk:** {event.get('risk')}",
                "color": 16711680,  # Red
                "timestamp": datetime.now().isoformat()
            }]
        }
        try:
            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"[NOTIFICATION] Failed to send webhook: {e}")
