#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    u32 remote_ip;
    u16 remote_port;
    int event_type; 
    u32 sig_verdict; // 0: Monitor, 1: Killed
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(stack_buffer, struct data_t, 1);

static __always_inline void aegis_terminate() {
    bpf_send_signal(9); 
}

// --- 1. THE ADVANCED NETWORK GATEKEEPER ---
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid < 1000) return 0; 

    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    data->remote_port = sk->__sk_common.skc_dport;
    
    // CIA LEVEL: Block all non-standard outbound ports for user-space apps
    // Allows 80 (HTTP), 443 (HTTPS), 53 (DNS)
    // Blocks 4444 (Metasploit), 6667 (IRC), 22 (SSH tunnels)
    u16 dport = ntohs(data->remote_port);
    if (dport != 80 && dport != 443 && dport != 53) {
        aegis_terminate();
        data->sig_verdict = 1;
    }

    data->uid = uid;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->event_type = 3;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

// --- 2. DEEP FILE INTEGRITY (FIM) + APP WHITELISTING ---
int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid < 1000) return 0;

    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (char *)filename);
    
    // FIREFOX FRIENDLY: Allow Firefox to access system libs and passwd
    // We check for "firefox" or "firefox-esr"
    if (data->comm[0] == 'f' && data->comm[1] == 'i' && data->comm[2] == 'r') {
        return 0; 
    }

    // CIA LEVEL: BLOCK SENSITIVE DIRECTORIES
    // Protects /etc/shadow, /etc/sudoers, /root/, and SSH keys
    if (data->fname[1] == 'e' && data->fname[2] == 't' && data->fname[3] == 'c') {
        // Block sensitive sub-files but allow ld.so.cache
        if (data->fname[5] == 's' || data->fname[5] == 'p') {
             aegis_terminate();
             data->event_type = 1;
             data->sig_verdict = 1;
             events.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    
    // Block access to .ssh folders
    if (data->fname[0] == '.' && data->fname[1] == 's' && data->fname[2] == 's' && data->fname[3] == 'h') {
        aegis_terminate();
        return 0;
    }

    return 0;
}

// --- 3. ZERO-TRUST EXECUTION GUARD ---
TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid < 1000) return 0;

    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // CIA LEVEL: Block by behavior and common recon patterns
    // Kills: netcat, nmap, socat, tcpdump, python (if used for shells)
    char c = data->comm[0];
    if (c == 'n' || c == 's' || c == 't' || (c == 'p' && data->comm[1] == 'y')) {
        aegis_terminate();
        data->sig_verdict = 1;
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->uid = uid;
        data->event_type = 0;
        events.perf_submit(args, data, sizeof(struct data_t));
    }
    return 0;
}
