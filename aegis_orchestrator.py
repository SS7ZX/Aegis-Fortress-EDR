from bcc import BPF
import os, json, sys, socket, struct
from datetime import datetime

# CLEAN LOG FILE ON START
LOG_FILE = "aegis_v5_intelligence.json"
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)

class AegisV5:
    def __init__(self):
        print("\033[92m[⚡] AEGIS v5.1: RECOVERY MODE ACTIVE\033[0m")
        self.b = BPF(src_file="sensor.c")

    def format_ip(self, ip_int):
        return socket.inet_ntoa(struct.pack("<L", ip_int))

    def process_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        ts = datetime.now().strftime('%H:%M:%S')
        comm = event.comm.decode(errors='replace')
        
        msg = ""
        if event.event_type == 3:
            msg = f"NET-BLOCK | Dest: {self.format_ip(event.remote_ip)}"
        elif event.event_type == 1:
            msg = f"FIM-BLOCK | Path: {event.fname.decode()}"
        elif event.event_type == 0:
            msg = f"EDR-BLOCK | Tool: {comm}"

        print(f"\033[91m[{ts}] KILL-SIGNAL SENT -> {comm} (PID:{event.pid}) | {msg}\033[0m")
        self.save_log(event, msg)

    def save_log(self, event, msg):
        with open(LOG_FILE, "a") as f:
            log = {"ts": datetime.now().isoformat(), "pid": event.pid, "comm": event.comm.decode(), "reason": msg}
            f.write(json.dumps(log) + "\n")

    def run(self):
        print("="*80)
        print("AEGIS FORTRESS v5.1 | SAFETY RAILS ENABLED (Targeting UID 1000+)")
        print("="*80)
        self.b["events"].open_perf_buffer(self.process_event)
        while True:
            try: self.b.perf_buffer_poll()
            except KeyboardInterrupt: break

if __name__ == "__main__":
    AegisV5().run()
