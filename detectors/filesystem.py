
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileIntegrityHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            self.callback({
                "type": "FILE_MODIFICATION",
                "path": event.src_path,
                "action": "MODIFIED",
                "risk": 80
            })

    def on_created(self, event):
        if not event.is_directory:
            self.callback({
                "type": "FILE_CREATION",
                "path": event.src_path,
                "action": "CREATED",
                "risk": 60
            })

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback({
                "type": "FILE_DELETION",
                "path": event.src_path,
                "action": "DELETED",
                "risk": 90
            })

class FileMonitor:
    def __init__(self, paths, event_callback):
        self.paths = paths
        self.observer = Observer()
        self.callback = event_callback

    def start(self):
        event_handler = FileIntegrityHandler(self.callback)
        for path in self.paths:
            try:
                self.observer.schedule(event_handler, path, recursive=False)
            except Exception as e:
                print(f"[!] Error monitoring {path}: {e}")
        
        self.observer.start()
        print("[*] File Integrity Monitor started.")

    def stop(self):
        self.observer.stop()
        self.observer.join()
