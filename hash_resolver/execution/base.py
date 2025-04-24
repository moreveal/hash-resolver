from abc import ABC, abstractmethod
from enum import Enum

class MAP_REGION(Enum):
    BASE = 0x0000
    FUNC_BYTES = 0x1000
    STUB_BYTES = 0x2000
    ALLOC = 0x3000

class ExecutionContext(ABC):
    # Interface
    @abstractmethod
    def write(self, addr: int, data: bytes): ...
    @abstractmethod
    def read(self, addr: int, size: int) -> bytes: ...
    @abstractmethod
    def reg_read(self, name: str) -> int: ...
    @abstractmethod
    def reg_write(self, name: str, value: int): ...
    @abstractmethod
    def alloc(self, size: int) -> int: ...
    def start(self, *args, **kwargs): raise NotImplementedError("Use run_stub(..., auto_wait=True) instead")
    @abstractmethod
    def run_stub(self, pattern, func_addr: int, args: list[int], auto_wait: bool = True): ...
    @abstractmethod
    def build_call_stub(self, pattern, func_addr: int, arg_values: list[int] = None) -> tuple[int, int]: ...
    @abstractmethod
    def cleanup(self) -> None: ...
    
    # Shared
    def get_map_region(self, region: MAP_REGION) -> int: return self.mem_base + region.value
