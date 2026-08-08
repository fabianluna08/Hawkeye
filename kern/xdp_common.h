/* kern/xdp_common.h
 * Structs compartidos entre el programa BPF (kernel) y el predictor C++.
 * Este header es incluido en AMBOS lados: kern/xdp_kern.c y src/predictor.cpp
 */
#pragma once
#ifndef BPF_KERNEL_SPACE
#include <linux/types.h>
/* struct bpf_spin_lock (usado abajo en ip_stats.lock) vive en linux/bpf.h,
 * no en linux/types.h. Se incluye explícitamente para que este header sea
 * autocontenido sin depender del orden de includes de quien lo use — hoy
 * predictor.cpp ya trae linux/bpf.h transitivamente vía bpf/bpf.h antes de
 * este include, pero no debería ser un requisito implícito. linux/bpf.h
 * tiene su propio include guard, así que esto es un no-op si ya estaba
 * incluido. */
#include <linux/bpf.h>
#endif

/* ── Tipos básicos ──────────────────────────────────────────── */
struct ip_key {
    __u32 ip[4]; /* ip[0] para IPv4; ip[0..3] para IPv6 */
    __u8 is_v6;
    __u8 pad[3]; /* Relleno explícito para evitar problemas del verificador eBPF */
};
typedef struct ip_key ip_key_t;
typedef __u8  block_val_t;

/* ── Constantes globales ────────────────────────────────────── */
#define MAX_IPS         1000000         /* 1M de IPs concurrentes (igual que tu original) */
#define WINDOW_NS       (1000000000ULL) /* Ventana de estadísticas: 1 segundo */

/* ── Token Bucket (tu lógica original, movida aquí para compartir) ─ */
#define REFILL_RATE_PPS 100             /* 100 paquetes/segundo permitidos por IP  */
#define BURST_SIZE      250             /* Ráfaga máxima: 250 paquetes            */
#define TOKEN_SCALE     1000            /* Factor de escala para evitar decimales  */

struct custom_token_bucket {
    __u64 tokens;       /* Tokens disponibles (escalados x TOKEN_SCALE) */
    __u64 last_refill;  /* Timestamp del último reabastecimiento (ns)   */
    __u32 burst_size;   /* Capacidad máxima del cubo                    */
    __u32 refill_rate;  /* Tasa de recarga (escalada x TOKEN_SCALE)     */
};

/* ── Estadísticas por IP para XGBoost ──────────────────────── *
 * Escritas por XDP cada paquete → leídas por el predictor C++ *
 * cada ~200ms para hacer inferencia.                          */
struct ip_stats {
    __u64 pkt_count;        /* Total de paquetes en la ventana            */
    __u64 byte_count;       /* Total de bytes en la ventana               */
    __u64 first_seen_ns;    /* Timestamp del primer paquete (ventana)     */
    __u64 last_seen_ns;     /* Timestamp del último paquete               */
    __u64 iat_sum_ns;       /* Suma de inter-arrival times (para media)   */
    __u64 dport_bitmap;     /* Bit i = se vio un paquete TCP con dest_port % 64 == i.
                              * El predictor C++ usa popcount(dport_bitmap) como
                              * aproximación real de "puertos destino únicos"      */
    __u32 syn_count;        /* Cantidad de paquetes con flag SYN          */
    __u32 udp_count;        /* Cantidad de paquetes UDP                   */
    __u32 icmp_count;       /* Cantidad de paquetes ICMP                  */
    __u32 tb_drops;         /* Paquetes descartados por Token Bucket      */

    /* Protege la secuencia completa "chequear ventana → resetear si
     * corresponde → incrementar" en kern/xdp_kern.c:update_ip_stats().
     * Antes solo first_seen_ns se reseteaba con CAS; los otros 7 campos se
     * reseteaban secuencialmente sin lock, dejando una ventana real donde
     * otra CPU podía incrementar un campo ya reseteado mientras otro seguía
     * con el valor viejo (ej. byte_count > 0 con pkt_count == 0).
     * Debe declararse a nivel superior del struct (no anidado) y solo se
     * puede tocar via bpf_spin_lock()/bpf_spin_unlock() — requisito del
     * verificador de eBPF. Visible en userspace via <linux/bpf.h> (incluido
     * transitivamente por <bpf/bpf.h> en predictor.cpp), incluida aquí para
     * que el layout de ip_stats coincida bit a bit entre kernel y userspace. */
    struct bpf_spin_lock lock;
};

/* ── Línea base global (Fase 0) ─────────────────────────────── *
 * Contadores planos, sin ventana ni por-IP: cuentan el 100% del
 * tráfico que llega al veredicto, para poder calcular después
 * (fuera del kernel) el % de tráfico cifrado y correlacionar con
 * alerts.jsonl/block_map la tasa real de flujos maliciosos. No
 * participan en ninguna decisión DROP/PASS. */
struct baseline_stats {
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 tcp443_pkts;
    __u64 tcp443_bytes;
    __u64 udp443_pkts;
    __u64 udp443_bytes;
};
