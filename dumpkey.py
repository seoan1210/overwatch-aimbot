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
            self.memory = self.safe_read_memory(self.base, self.size)
        except Exception:
            exit()

    def safe_read_memory(self, start_addr, size):
        buffer = bytearray()
        for i in range(0, size, 4096):
            try: buffer.extend(self.pm.read_bytes(start_addr + i, 4096))
            except: buffer.extend(b'\x00' * 4096)
        return bytes(buffer)

    def get_rip(self, address, offset, ins_size):
        try:
            rel = struct.unpack('<i', self.pm.read_bytes(address + offset, 4))[0]
            return address + rel + ins_size
        except: return 0

    def find_all(self, pattern):
        regex = b"".join([b"." if p in ("?", "??") else re.escape(bytes.fromhex(p)) for p in pattern.split()])
        return [self.base + m.start() for m in re.finditer(regex, self.memory, re.DOTALL)]

    def dump_everything(self):
        print("\n" + "="*60)
        print("          OVERWATCH FULL DATA RESULTS")
        print("="*60)

        ent_patterns = [
            "48 8B 0D ? ? ? ? 48 85 C9 74 ? 48 8B 01 48 FF 60 ? 48 8B D1",
            "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 07",
            "48 03 0D ? ? ? ? 74 60"
        ]
        
        found_ent = False
        for p in ent_patterns:
            matches = self.find_all(p)
            for m in matches:
                addr = self.get_rip(m, 3, 7)
                try:
                    if addr > self.base and self.pm.read_longlong(addr) != 0:
                        print(f"ENTITY_ADMIN      : {hex(addr)}")
                        found_ent = True
                        break
                except: continue
            if found_ent: break

        vm_sig = self.find_all("48 8B 05 ? ? ? ? 49 BE ? ? ? ? ? ? ? ? 49 33 C6")
        if not vm_sig:
            vm_sig = self.find_all("48 8B 05 ? ? ? ? 48 8B D9 48 85 C0 74")
            
        if vm_sig:
            vm_addr = vm_sig[0]
            print(f"VIEW_MATRIX_BASE  : {hex(self.get_rip(vm_addr, 3, 7))}")
            print(f"VM_XOR_KEY        : {hex(struct.unpack('<Q', self.pm.read_bytes(vm_addr + 9, 8))[0])}")

        print(f"DECRYPT_BYTE_OFF  : 0x3646851")
        print(f"QWORD_PTR_OFF     : 0x3947AF8")
        
        try:
            byte_val = self.pm.read_uchar(self.base + 0x3646851)
            print(f"DECRYPT_BYTE_VAL  : {hex(byte_val)}")
        except: pass

        sens_sig = self.find_all("F3 0F 10 83 ? ? ? ? F3 0F 59 05")
        if sens_sig:
            sens_off = struct.unpack('<I', self.pm.read_bytes(sens_sig[0] + 4, 4))[0]
            print(f"SENSITIVITY_OFF   : {hex(sens_off)}")

        print("="*60)

if __name__ == "__main__":
    tracker = OverwatchMasterTracker()
    tracker.dump_everything()
