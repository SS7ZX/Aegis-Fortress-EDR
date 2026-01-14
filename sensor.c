#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    u32 remote_ip;
    int event_type; // 0=EXEC, 1=OPEN, 2=DELETE, 3=NET_CONNECT
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(stack_buffer, struct data_t, 1);

// WORLD-CLASS HELPER: Instant Termination from Kernel Space
static __always_inline void aegis_terminate() {
    bpf_send_signal(9); // Send SIGKILL immediately
}

// 1. NETWORK SHIELD: Block Unauthorized Outbound Connections
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    data->uid = bpf_get_current_uid_gid();
    if (data->uid != 0) { // If not root, block external TCP
        data->remote_ip = sk->__sk_common.skc_daddr;
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->event_type = 3;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        
        aegis_terminate(); // KILL before handshake completes
        events.perf_submit(ctx, data, sizeof(struct data_t));
    }
    return 0;
}

// 2. HARDENED FIM: Blocks Access to System Files
int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename) {
    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (char *)filename);
    data->uid = bpf_get_current_uid_gid();

    // Check for sensitive path (/etc/)
    if (data->fname[1] == 'e' && data->fname[2] == 't' && data->fname[3] == 'c') {
        if (data->uid != 0) {
            aegis_terminate(); // INSTANT DEATH
            data->pid = bpf_get_current_pid_tgid() >> 32;
            data->event_type = 1;
            bpf_get_current_comm(&data->comm, sizeof(data->comm));
            events.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    return 0;
}

// 3. HARDENED EDR: Blocks Blacklisted Tools
TRACEPOINT_PROBE(sched, sched_process_exec) {
    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->uid = bpf_get_current_uid_gid();

    // Kernel-side pattern matching for blacklisted tools (n=nc/nmap, t=tcpdump, s=socat)
    if (data->uid != 0 && (data->comm[0] == 'n' || data->comm[0] == 't' || data->comm[0] == 's')) {
        aegis_terminate();
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->event_type = 0;
        TP_DATA_LOC_READ_CONST(&data->fname, filename, 256);
        events.perf_submit(args, data, sizeof(struct data_t));
    }
    return 0;
}
