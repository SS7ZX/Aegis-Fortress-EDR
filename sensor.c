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
    int event_type; 
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(stack_buffer, struct data_t, 1);

static __always_inline void aegis_terminate() {
    bpf_send_signal(9); 
}

// 1. NETWORK SHIELD WITH SAFETY RAILS
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid < 1000) return 0; // SAFETY: Ignore System/Root services

    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    data->uid = uid;
    data->remote_ip = sk->__sk_common.skc_daddr;
    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->event_type = 3;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    aegis_terminate(); 
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 0;
}

// 2. FIM WITH SAFETY RAILS
int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid < 1000) return 0; // SAFETY: Don't kill the OS display manager!

    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    bpf_probe_read_user_str(&data->fname, sizeof(data->fname), (char *)filename);
    
    if (data->fname[1] == 'e' && data->fname[2] == 't' && data->fname[3] == 'c') {
        aegis_terminate(); 
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->uid = uid;
        data->event_type = 1;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        events.perf_submit(ctx, data, sizeof(struct data_t));
    }
    return 0;
}

// 3. EDR WITH SAFETY RAILS
TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 uid = bpf_get_current_uid_gid();
    if (uid < 1000) return 0; // SAFETY

    int zero = 0;
    struct data_t *data = stack_buffer.lookup(&zero);
    if (!data) return 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // Pattern match: nc, nmap, socat, tcpdump
    if (data->comm[0] == 'n' || data->comm[0] == 's' || data->comm[0] == 't') {
        aegis_terminate();
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->uid = uid;
        data->event_type = 0;
        events.perf_submit(args, data, sizeof(struct data_t));
    }
    return 0;
}
