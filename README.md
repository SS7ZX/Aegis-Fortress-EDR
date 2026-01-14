

![Status](https://img.shields.io/badge/Status-Active_Protective-success?style=for-the-badge&logo=shield)
![Security](https://img.shields.io/badge/Detection-eBPF_Kernel-blue?style=for-the-badge&logo=linux)
![Mitigation](https://img.shields.io/badge/Mitigation-SIGKILL_Enabled-red?style=for-the-badge&logo=target)

# AEGIS FORTRESS EDR v5.1
... (rest of your content)# AEGIS FORTRESS EDR v5.1

### Kernel-Native Threat Detection & Neutralization
Aegis Fortress is a high-performance Endpoint Detection and Response (EDR) suite leveraging **eBPF** (Extended Berkeley Packet Filter) to monitor and block unauthorized system activities at the kernel level.

## 🚀 Key Features
* **eBPF Sensor:** Real-time monitoring of sensitive file access (FIM).
* **Automated Neutralization:** Blocks unauthorized UIDs from accessing critical system files.
* **Python Orchestrator:** High-level management and logging of kernel events.
* **Forensic Logging:** Exports detections to CSV for SIEM integration.

## 🛠️ Architecture

The system hooks into the `vfs_read` kernel function, allowing Aegis to intercept file read requests before they are completed.

## 📋 Installation & Usage
1. **Compile the sensor:** `python3 aegis_orchestrator.py`
2. **Monitor logs:** `tail -f threat_log.csv`

---
*Developed by SS7ZX*
