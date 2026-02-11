import psutil
from Collectors.base_collectors import BaseCollector

class LinuxCollector(BaseCollector):

    def get_processes(self):
        processes = []
        for p in psutil.process_iter(['pid', 'name', 'exe']):
            processes.append(p.info)
        return processes

    def get_network_connections(self):
        return psutil.net_connections(kind='inet')

    def get_startup_items(self):
        return []  # v1.0
