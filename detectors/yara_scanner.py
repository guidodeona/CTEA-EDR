
import yara
import os
import logging

class YaraScanner:
    def __init__(self, rules_path):
        self.rules = None
        self.rules_path = rules_path
        self.load_rules()

    def load_rules(self):
        try:
            if not os.path.exists(self.rules_path):
                logging.error(f"[YARA] Rules not found at {self.rules_path}")
                return
            
            self.rules = yara.compile(filepath=self.rules_path)
            logging.info("[YARA] Rules loaded successfully.")
        except Exception as e:
            logging.error(f"[YARA] Failed to compile rules: {e}")

    def scan_file(self, file_path):
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(file_path)
            return self._format_matches(matches, file_path, "FILE")
        except Exception as e:
            # Common error: Access denied
            # logging.debug(f"[YARA] Error scanning file {file_path}: {e}")
            return []

    def scan_process(self, pid, process_name):
        if not self.rules:
            return []

        try:
            # requires Administrative privileges 
            matches = self.rules.match(pid=int(pid))
            return self._format_matches(matches, process_name, "PROCESS_MEMORY")
        except yara.Error as e:
            # Often permission denied or process exited
            return []
        except Exception as e:
            logging.error(f"[YARA] Unexpected error scanning PID {pid}: {e}")
            return []

    def _format_matches(self, matches, target, scan_type):
        events = []
        for match in matches:
            events.append({
                "type": "YARA_MATCH",
                "risk": 100, # High confidence if Yara matches
                "name": f"{match.rule} detected in {target}",
                "details": f"Rule: {match.rule}, Tags: {match.tags}, Meta: {match.meta}",
                "scan_type": scan_type
            })
        return events
