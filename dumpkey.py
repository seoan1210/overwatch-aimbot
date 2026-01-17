import pymem
import pymem.process
import struct
import re

class OverwatchKeyFinder:
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
        if not addr: return 0
        rel = struct.unpack('<i', self.pm.read_bytes(addr + offset, 4))[0]
        return addr + rel + ins_size

    def scan(self):
        keys = {}
        
        ent_sig = "48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 01 48 FF 60 ? 48 8B D1"
        keys['ENTITY_ADMIN'] = self.get_rip(self.find_pattern(ent_sig), 3, 7)

        vm_sig = "48 8B 05 ? ? ? ? 49 BE ? ? ? ? ? ? ? ? 49 33 C6"
        vm_match = self.find_pattern(vm_sig)
        if vm_match:
            keys['VM_BASE'] = self.get_rip(vm_match, 3, 7)
            keys['VM_XOR'] = struct.unpack('<Q', self.pm.read_bytes(vm_match + 9, 8))[0]

        sens_sig = "F3 0F 10 83 ? ? ? ? F3 0F 59 05"
        sens_match = self.find_pattern(sens_sig)
        if sens_match:
            keys['SENS_OFF'] = struct.unpack('<I', self.pm.read_bytes(sens_match + 4, 4))[0]

        local_sig = "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 07"
        keys['LOCAL_BASE'] = self.get_rip(self.find_pattern(local_sig), 3, 7)

        for k, v in keys.items():
            print(f"{k.ljust(15)} : {hex(v) if isinstance(v, int) else v}")
        return keys

if __name__ == "__main__":
    OverwatchKeyFinder().scan()
