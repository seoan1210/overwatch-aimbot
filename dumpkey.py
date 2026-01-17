import pymem
import pymem.process
import struct
import re

class OverwatchMasterTracker:
    def __init__(self):
        try:
            self.pm = pymem.Pymem("Overwatch.exe")
            self.module = pymem.process.module_from_name(self.pm.process_handle, "Overwatch.exe")
            self.base = self.module.lpBaseOfDll
            self.size = self.module.SizeOfImage
            self.memory = self.pm.read_bytes(self.base, self.size)
        except:
            exit()

    def find_pattern(self, pattern):
        regex = b"".join([b"." if p in ("?", "??") else re.escape(bytes.fromhex(p)) for p in pattern.split()])
        match = re.search(regex, self.memory, re.DOTALL)
        return self.base + match.start() if match else None

    def get_rip(self, addr, offset, ins_size):
        if not addr: return None
        rel = struct.unpack('<i', self.pm.read_bytes(addr + offset, 4))[0]
        return addr + rel + ins_size

    def dump(self):
        results = {}
        
        ent_ptr = self.find_pattern("48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 01 48 FF 60 ? 48 8B D1")
        results['ENTITY_ADMIN'] = hex(self.get_rip(ent_ptr, 3, 7) or 0)

        vm_ptr = self.find_pattern("48 8B 05 ? ? ? ? 49 BE ? ? ? ? ? ? ? ? 49 33 C6")
        if vm_ptr:
            results['VIEW_MATRIX'] = hex(self.get_rip(vm_ptr, 3, 7) or 0)
            results['VM_XOR_KEY'] = hex(struct.unpack('<Q', self.pm.read_bytes(vm_ptr + 9, 8))[0])

        sens_ptr = self.find_pattern("F3 0F 10 83 ? ? ? ? F3 0F 59 05")
        if sens_ptr:
            results['SENS_OFF'] = hex(struct.unpack('<I', self.pm.read_bytes(sens_ptr + 4, 4))[0])

        for k, v in results.items():
            print(f"{k.ljust(18)}: {v}")

if __name__ == "__main__":
    OverwatchMasterTracker().dump()
