from bcc import BPF
import os, signal, json, sys, socket, struct
from datetime import datetime

class AegisV5:
    def __init__(self):
        print("\033[95m[⚡] INITIALIZING AEGIS v5.0: ZERO-TRUST KERNEL CORE\033[0m")
        self.b = BPF(src_file="sensor.c")
        self.log_file = "aegis_v5_intelligence.json"

    def format_ip(self, ip_int):
        return socket.inet_ntoa(struct.pack("<L", ip_int))

    def process_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        ts = datetime.now().strftime('%H:%M:%S')
        comm = event.comm.decode(errors='replace')
        
        # LOGIC MAPPING
        if event.event_type == 3: # NETWORK
            rip = self.format_ip(event.remote_ip)
            print(f"\033[41m[{ts}] NET-KILL | {comm} (PID:{event.pid}) attempted connection to {rip}! TERMINATED.\033[0m")
        elif event.event_type == 1: # FIM
            path = event.fname.decode(errors='replace')
            print(f"\033[91m[{ts}] FIM-KILL | {comm} attempted to read {path}! TERMINATED.\033[0m")
        elif event.event_type == 0: # EDR
            print(f"\033[1;91m[{ts}] EDR-KILL | Blacklisted tool '{comm}' execution blocked! TERMINATED.\033[0m")
        
        self.save_log(event)

    def save_log(self, event):
        with open(self.log_file, "a") as f:
            f.write(json.dumps({
                "ts": datetime.now().isoformat(),
                "pid": event.pid,
                "uid": event.uid,
                "comm": event.comm.decode(),
                "type": event.event_type
            }) + "\n")

    def run(self):
        print("="*80)
        print("AEGIS FORTRESS v5.0 | SYSTEM PROTECTED BY KERNEL-SPACE ENFORCEMENT")
        print("="*80)
        self.b["events"].open_perf_buffer(self.process_event)
        while True:
            try: self.b.perf_buffer_poll()
            except KeyboardInterrupt: break

if __name__ == "__main__":
    AegisV5().run()

