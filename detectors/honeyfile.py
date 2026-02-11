
import os
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class HoneyfileHandler(FileSystemEventHandler):
    def __init__(self, filename, callback):
        self.filename = os.path.basename(filename)
        self.callback = callback

    def on_any_event(self, event):
        # Check if the event is related to our honeyfile
        if event.src_path.endswith(self.filename):
            self.callback({
                "type": "HONEYFILE_TRIGGERED",
                "risk": 100,
                "name": "Access to Honeyfile Detected",
                "details": f"Action: {event.event_type} on {self.filename}",
                "action": "BLOCK" 
            })

class HoneyfileMonitor:
    def __init__(self, filepath, callback):
        self.filepath = filepath
        self.callback = callback
        self.observer = None
        self.dir_path = os.path.dirname(filepath)

    def setup_trap(self):
        """Creates the honeyfile if it doesn't exist."""
        try:
            if not os.path.exists(self.filepath):
                with open(self.filepath, "w") as f:
                    f.write("CONFIDENTIAL - DO NOT OPEN - PASSWORDS DETECTED")
                logging.info(f"[HONEYFILE] Trap placed at {self.filepath}")
            else:
                logging.info(f"[HONEYFILE] Using existing trap at {self.filepath}")
        except Exception as e:
            logging.error(f"[HONEYFILE] Failed to create trap: {e}")

    def start(self):
        self.setup_trap()
        self.observer = Observer()
        event_handler = HoneyfileHandler(self.filepath, self.callback)
        
        try:
            self.observer.schedule(event_handler, self.dir_path, recursive=False)
            self.observer.start()
            logging.info("[HONEYFILE] Monitoring active.")
        except Exception as e:
            logging.error(f"[HONEYFILE] Error starting monitor: {e}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
