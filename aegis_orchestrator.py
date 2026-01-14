from bcc import BPF
import os, json, sys, socket, struct
from datetime import datetime

# LOG FILENAME WITH DATE FOR FORENSIC AUDITING
LOG_FILE = f"aegis_intel_{datetime.now().strftime('%Y%m%d')}.json"

class AegisIntelligence:
    def __init__(self):
        print("\033[1;34m[✦] INITIALIZING AEGIS BEYOND-CIA KERNEL SENTRY...\033[0m")
        try:
            self.b = BPF(src_file="sensor.c")
            print("\033[1;32m[✔] KERNEL HOOKS ATTACHED | ZERO-TRUST MODE ACTIVE\033[0m")
        except Exception as e:
            print(f"\033[1;31m[✘] FATAL: FAILED TO LOAD KERNEL SENSOR: {e}\033[0m")
            sys.exit(1)

    def resolve_hostname(self, ip_str):
        """Beyond CIA: Resolve IPs to hostnames to identify C2 servers."""
        try:
            return socket.gethostbyaddr(ip_str)[0]
        except:
            return "Unknown/External"

    def format_ip(self, ip_int):
        return socket.inet_ntoa(struct.pack("<L", ip_int))

    def process_event(self, cpu, data, size):
        # Unpack the C structure from the kernel
        event = self.b["events"].event(data)
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        comm = event.comm.decode(errors='replace')
        
        # Determine Severity and Verdict
        verdict = "TERMINATED" if event.sig_verdict == 1 else "MONITORED"
        color = "\033[1;31m" if event.sig_verdict == 1 else "\033[1;32m"
        
        intel = ""
        if event.event_type == 3: # NETWORK
            ip_str = self.format_ip(event.remote_ip)
            port = socket.ntohs(event.remote_port)
            hostname = self.resolve_hostname(ip_str)
            intel = f"📡 NET: {ip_str}:{port} ({hostname})"
        elif event.event_type == 1: # FIM
            path = event.fname.decode(errors='ignore')
            intel = f"📂 FILE: {path}"
        elif event.event_type == 0: # EXEC
            intel = f"🚀 EXEC: Binary Launch Detected"

        # CIA-STYLE CONSOLE OUTPUT
        print(f"{color}[{ts}] {verdict:<10} | {comm:<15} (PID:{event.pid:<6}) | {intel}\033[0m")
        
        self.save_forensics(event, intel, verdict)

    def save_forensics(self, event, intel, verdict):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "pid": event.pid,
            "uid": event.uid,
            "process": event.comm.decode(errors='replace'),
            "action": verdict,
            "intel": intel,
            "threat_level": "CRITICAL" if verdict == "TERMINATED" else "LOW"
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def run(self):
        print("\033[1;37m" + "="*90 + "\033[0m")
        print(f"{'TIMESTAMP':<13} | {'VERDICT':<10} | {'PROCESS':<15} | {'PID':<6} | {'THREAT INTELLIGENCE'}")
        print("\033[1;37m" + "="*90 + "\033[0m")
        
        self.b["events"].open_perf_buffer(self.process_event)
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n\033[1;33m[!] SHUTTING DOWN SENTRY... SECURING LOGS.\033[0m")
                break

if __name__ == "__main__":
    AegisIntelligence().run()
