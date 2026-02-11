import time
import platform
import yaml
import os
from Core.responder import ThreatResponder
from Core.analyzer import ThreatAnalyzer
from detectors.process import detect_suspicious_processes
from detectors.network import detect_suspicious_connections
from detectors.virustotal import scan_processes_with_virustotal
from detectors.filesystem import FileMonitor
from detectors.yara_scanner import YaraScanner
from detectors.persistence import PersistenceMonitor
from detectors.honeyfile import HoneyfileMonitor

class CTEAEngine:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.rules = self._load_rules()
        self.collector = self._get_collector()
        
        # File Integrity Monitoring Setup
        self.file_events = []
        monitored_paths = self.rules.get('filesystem', {}).get('monitored_paths', {}).get(self.os_type, [])
        self.file_monitor = FileMonitor(monitored_paths, self._file_event_callback)
        
        # Honeyfile Setup
        self.honeyfile_events = []
        hf_config = self.rules.get('honeyfile', {})
        if hf_config.get('enabled'):
            self.honeyfile_monitor = HoneyfileMonitor(hf_config['path'], self._honeyfile_event_callback)
        else:
            self.honeyfile_monitor = None

        # Persistence Setup
        self.persistence_monitor = PersistenceMonitor(self.rules.get('persistence', {}).get('registry_keys'))

        # Yara Setup
        yara_config = self.rules.get('yara', {})
        if yara_config.get('enabled') and yara_config.get('rules_path'):
             self.yara_scanner = YaraScanner(yara_config['rules_path'])
        else:
             self.yara_scanner = None

    def _file_event_callback(self, event):
        """Callback for file system events. Appends to queue."""
        self.file_events.append(event)
        
    def _honeyfile_event_callback(self, event):
        """Callback for honeyfile events."""
        print(f"[!!!] HONEYFILE TRIGGERED: {event}")
        self.honeyfile_events.append(event)

    def _load_rules(self):
        try:
            with open("config/rules.yaml", "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading rules: {e}")
            # Return a default ruleset if loading fails
            return {
                'risk_thresholds': {'high': 80, 'medium': 50, 'low': 20},
                'process': {'suspicious_paths': {'windows': [], 'linux': []}}
            }

    def _get_collector(self):
        if self.os_type == "windows":
            from Collectors.windows import WindowsCollector
            return WindowsCollector()
        elif self.os_type == "linux":
            from Collectors.linux import LinuxCollector
            return LinuxCollector()
        else:
            raise NotImplementedError(f"OS {self.os_type} not supported")

    def run_daemon(self):
        print("[*] CTEA iniciado en modo monitoreo continuo")
        
        # Start File Monitor in background
        if self.file_monitor.paths:
            self.file_monitor.start()

        if self.honeyfile_monitor:
            self.honeyfile_monitor.start()
            
        while True:
            severity, score, events = self.run()

            if severity in ["MEDIUM", "HIGH"]:
                print(f"[!] Amenaza detectada: {severity} ({score})")
            time.sleep(30)
            
    def run(self):
        processes = self.collector.get_processes()

        events = detect_suspicious_processes(
            processes, self.rules, self.os_type
        )

        connections = self.collector.get_network_connections()
        network_events = detect_suspicious_connections(connections, self.rules)
        events.extend(network_events)

        # VIRUSTOTAL CHECK
        vt_config = self.rules.get('virustotal', {})
        if vt_config.get('enabled') and vt_config.get('api_key'):
             try:
                vt_events = scan_processes_with_virustotal(
                    processes, 
                    vt_config['api_key'],
                    limit=3 # strict limit to avoid blocking
                )
                events.extend(vt_events)
             except Exception as e:
                print(f"[!] VirusTotal Error: {e}")

        # YARA SCAN (Scan executables of running processes)
        if self.yara_scanner:
            for proc_info in processes:
                try:
                    # Scan the executable file on disk (safer/faster than memory)
                    exe_path = proc_info.get('exe')
                    if exe_path and os.path.exists(exe_path):
                        matches = self.yara_scanner.scan_file(exe_path)
                        if matches:
                            # Enrich with process info
                            for m in matches:
                                m['pid'] = proc_info['pid'] 
                                m['name'] = f"{proc_info['name']} (YARA)"
                            events.extend(matches)
                except Exception:
                    pass

        # PERSISTENCE CHECK
        if self.persistence_monitor:
            p_events = self.persistence_monitor.check_changes()
            if p_events:
                events.extend(p_events)

        # FILE SYSTEM & HONEYFILE EVENTS
        if self.honeyfile_events:
             events.extend(self.honeyfile_events)
             self.honeyfile_events = [] # Clear queue

        if self.file_events:
            print(f"[*] Processing {len(self.file_events)} file system events...")
            events.extend(self.file_events)
            self.file_events = [] # Clear queue after processing

        analyzer = ThreatAnalyzer(self.rules)
        analyzer.add_events(events)

        severity, score = analyzer.evaluate()

        # Get Webhook URL from rules
        webhook_url = None
        if self.rules.get('notifications', {}).get('enabled'):
             webhook_url = self.rules.get('notifications', {}).get('webhook_url')

        responder = ThreatResponder(webhook_url)
        responder.respond(severity, events)

        return severity, score, events
