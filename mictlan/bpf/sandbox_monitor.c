#include <linux/sched.h>

/* tainted_pids: marca que PIDs pertenecen al arbol de procesos de Firecracker
 * (el PID inicial que lanza orchestrator.py, mas todo lo que ese proceso o
 * sus descendientes lleguen a fork/clone). Antes esto se aproximaba mirando
 * si comm empezaba con "fire" en sys_enter_execve -- evadible con
 * prctl(PR_SET_NAME, ...) antes de escapar, y ademas no cubria execveat ni
 * ningun proceso hijo con un comm distinto. Ahora se seguie por PID real via
 * este mapa, propagado en cada fork (ver sched_process_fork mas abajo), asi
 * que cubre toda la cadena de procesos sin importar como se llamen.
 *
 * monitor.py es quien escribe la entrada inicial (recibe el PID de
 * Firecracker via el socket IPC de orchestrator.py, ver escape_monitor_ipc.py)
 * -- este programa BPF solo LEE el mapa en execve/execveat y lo PROPAGA en
 * fork; nunca inserta la marca inicial por su cuenta.
 */
BPF_HASH(tainted_pids, u32, u8);

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[128];
    u8  via_execveat; /* 0 = execve, 1 = execveat */
};

BPF_PERF_OUTPUT(events);

/* Firecracker (o cualquier descendiente marcado como tainted) NUNCA deberia
 * hacer execve/execveat en el host -- esta disenado para ejecutar codigo del
 * guest de forma interna y controlada. Si un PID tainted llama a cualquiera
 * de los dos, es una fuga de sandbox real. */
static inline int report_if_tainted(void *ctx, const char *filename_ptr, u8 via_execveat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *marked = tainted_pids.lookup(&pid);
    if (!marked)
        return 0;

    struct data_t data = {};
    data.pid = pid;
    data.via_execveat = via_execveat;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename_ptr);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    return report_if_tainted(args, args->filename, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    return report_if_tainted(args, args->filename, 1);
}

/* Propaga la marca "tainted" del padre al hijo en cada fork/clone -- asi
 * cubre toda la cadena de procesos que Firecracker (u otro PID ya marcado)
 * llegue a generar, no solo el PID inicial. */
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 ppid = args->parent_pid;
    u8 *marked = tainted_pids.lookup(&ppid);
    if (marked) {
        u32 cpid = args->child_pid;
        u8 one = 1;
        tainted_pids.update(&cpid, &one);
    }
    return 0;
}

/* Limpieza: sin esto, tainted_pids crece sin limite con cada PID marcado que
 * termina (el arbol de Firecracker genera y destruye procesos en cada
 * detonacion efimera). */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = args->pid;
    tainted_pids.delete(&pid);
    return 0;
}
