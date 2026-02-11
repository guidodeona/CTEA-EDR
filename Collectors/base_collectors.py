from abc import ABC, abstractmethod

class BaseCollector(ABC):

    @abstractmethod
    def get_processes(self):
        pass

    @abstractmethod
    def get_network_connections(self):
        pass

    @abstractmethod
    def get_startup_items(self):
        pass
