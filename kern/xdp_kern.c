/* kern/xdp_kern.c
 *
 * Programa XDP integrado — DDoS Guardian
 * Combina tres capas de defensa:
 *
 *   CAPA 1 — Bloqueo duro (escrito por predictor C++/XGBoost)
 *             Consulta block_map antes de cualquier procesamiento.
 *             Si la IP está marcada → XDP_DROP inmediato.
 *
 *   CAPA 2 — Token Bucket (tu lógica original, sin cambios de comportamiento)
 *             Limita la tasa de cada IP a REFILL_RATE_PPS paquetes/segundo.
 *             Actúa como red de seguridad mientras XGBoost no ha decidido aún.
 *
 *   CAPA 3 — Recolección de estadísticas (nueva)
 *             Actualiza ip_stats_map con métricas que el predictor C++
 *             leerá cada 200ms para hacer inferencia con XGBoost.
 *
 * Compilar:
 *   make kern
 *   (o directamente: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *    -I/usr/include/x86_64-linux-gnu -Ikern/ -c kern/xdp_kern.c -o xdp_kern.o)
 */

/* vmlinux.h se genera con: bpftool btf dump file /sys/kernel/btf/vmlinux format c */
#define BPF_KERNEL_SPACE
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_common.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* ════════════════════════════════════════════════════════════
 * MAPAS BPF
 * ════════════════════════════════════════════════════════════ */

/* ── Mapa 1: Token Bucket (tu mapa original, sin cambios) ── */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key,   ip_key_t);
    __type(value, struct custom_token_bucket);
} rate_limit_map SEC(".maps");

/* ── Mapa 2: Estadísticas por IP → leído por el predictor C++ ──
 * HASH, no LRU_HASH: confirmado en runtime (kernel 7.0.13) que el kernel
 * rechaza crear un mapa LRU_HASH con BTF cuando el value tiene un
 * bpf_spin_lock (bpf_create_map_xattr devuelve -EOPNOTSUPP, libbpf reintenta
 * silenciosamente sin BTF, y el verifier termina rechazando el programa con
 * "map has to have BTF in order to use bpf_spin_lock"). No se pierde
 * protección real: el predictor C++ ya borra explícitamente las IPs
 * inactivas (>5s) y las bloqueadas en cada ciclo de poll (50ms) — la
 * eviction de LRU era una red de seguridad redundante con esa limpieza, no
 * el mecanismo principal de acotar el tamaño del mapa. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key,   ip_key_t);
    __type(value, struct ip_stats);
} ip_stats_map SEC(".maps");

/* ── Mapa 3: IPs bloqueadas → escrito por el predictor C++  ── *
 * Fast-path: XDP consulta esto ANTES que cualquier otra cosa.  */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key,   ip_key_t);
    __type(value, block_val_t);
} block_map SEC(".maps");

/* ── Mapa 5: IPs en Lista Blanca (Whitelist) → escrito por API/userspace ── *
 * Fast-path 0: XDP permite pasar (PASS) estas IPs ANTES de revisar block_map. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   ip_key_t);
    __type(value, __u8);
} whitelist_map SEC(".maps");

/* ── Mapa 4: Contador de drops por CPU (tu mapa original) ── */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

/* ── Mapa 6: Línea base global (Fase 0) → leído por scripts/baseline_report.py ── *
 * Per-CPU, 1 entrada: contadores planos de todo el tráfico que llega al
 * veredicto, sin ventana ni por-IP. No es señal para XGBoost, es solo
 * medición para calcular el presupuesto de falsos positivos de fases futuras. */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct baseline_stats);
} baseline_map SEC(".maps");

/* ── Mapa 7: sockets AF_XDP propios (Fase 1) ── *
 * DOS mapas dedicados, uno por interfaz física (slot 0 -> xsks_map_a,
 * slot 1 -> xsks_map_b), en vez de UN xsks_map compartido indexado por
 * slot. Bug encontrado 2026-08-05 (diagnosticado a fondo, causa exacta
 * en el kernel no confirmada): con un solo xsks_map compartido entre
 * enp1s0 y enp3s0 (NICs físicas reales, driver igc), un socket AF_XDP
 * insertado correctamente desde userspace (bpf_map_update_elem sin
 * error, mismo mecanismo exacto que xsk_socket__update_xskmap()) queda
 * invisible para el propio programa corriendo en modo XDP — un
 * bpf_map_lookup_elem() DIRECTO sobre esa entrada, hecho desde DENTRO
 * del programa, devuelve NULL el 100% de las veces (cientos de miles de
 * paquetes, descartado nativo/genérico, ifindex, queue_id — todos
 * coinciden correctamente, ver commits del 2026-08-05). El mismo
 * mecanismo (mapa único compartido, mismo código) funciona sin falla en
 * veth, incluso siendo esclavas de un bridge de prueba — la única
 * variable que quedó sin poder aislar fue "mapa único compartido entre
 * 2 interfaces físicas reales". Un xskmap DEDICADO por interfaz (1 sola
 * entrada cada uno, key=0 siempre) evita esa combinación por completo. */
struct {
    __uint(type,        BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} xsks_map_a SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} xsks_map_b SEC(".maps");

/* ── Mapa 8: configuración de triaje (Fase 1) → escrito por userspace ── *
 * key = ifindex de una interfaz FÍSICA donde predictor.cpp adjuntó este
 * programa (ver load_bpf()/setup_triage() — acepta una lista de
 * interfaces, típicamente los dos esclavos físicos de un bridge), value =
 * "slot" (0 -> xsks_map_a, 1 -> xsks_map_b) que le corresponde a ESA
 * interfaz — CAPA 4 lo usa para elegir a CUÁL de los dos mapas redirigir
 * (no hay un mapa único compartido, ver comentario de xsks_map_a/b).
 *
 * Por qué por-interfaz y no un solo qid global (bug encontrado 2026-08-05,
 * ver comentario largo en CAPA 4 más abajo): este appliance es un bridge
 * transparente de 2 puertos (enp1s0 ↔ enp3s0 vía br0) — adjuntar el
 * programa a br0 (el master) NUNCA ve tráfico genuinamente forwardeado
 * entre los esclavos (el kernel no vuelve a invocar el hook de recepción
 * del bridge master para eso, solo para tráfico entregado localmente).
 * Hay que adjuntar el programa a CADA física por separado; como
 * bpf_redirect_map hacia un XSKMAP exige que el socket destino esté
 * bindeado a la MISMA interfaz por la que ingresó el paquete, hace falta
 * saber, para el ifindex de ESTE paquete, cuál es su interfaz — de ahí
 * este mapa. */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key,   __u32);
    __type(value, __u32);
} ifindex_slot SEC(".maps");

/* ── Mapa 9 (temporal, diagnóstico 2026-08-05): contadores de CAPA 4 ── *
 * key 0 = paquetes que llegan a CAPA 4 (pasaron CAPA 0-3)
 * key 1 = matchean is_inspected_port() y disparan bpf_redirect_map()
 * key 2 = ifindex_slot tenía entrada para la interfaz de ingreso
 * key 3 = proto == TCP,  key 4 = TCP dport==443, key 5 = TCP dport==80,
 * key 6 = TCP dport==445/sport==445, key 7 = proto == UDP
 * key 8 = bpf_redirect_map() devolvió XDP_REDIRECT (encolado real)
 * key 9 = bpf_redirect_map() devolvió el fallback (XDP_PASS) — el lookup
 *         interno al slot de xsks_map falló pese a que ifindex_slot
 *         SÍ tenía entrada (key 2)
 * key 10 = *slot leído de ifindex_slot fue 0, key 11 = fue 1,
 * key 12 = fue >=2 (inesperado, con solo 2 interfaces nunca debería pasar)
 * key 13 = bpf_map_lookup_elem() DIRECTO sobre xsks_map[*slot] encontró
 *          algo, key 14 = no encontró nada (NULL) — aísla si el problema
 *          es el contenido del mapa o específicamente bpf_redirect_map()
 * Leer con `sudo bpftool map dump name capa4_dbg_map`. Sacar este mapa
 * (y los incrementos asociados) una vez confirmado dónde se corta el
 * flujo — ver riesgo R5 en MANUAL_TECNICO.md. */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);
    __type(key,   __u32);
    __type(value, __u64);
} capa4_dbg_map SEC(".maps");

static __always_inline void capa4_dbg_inc(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&capa4_dbg_map, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}


/* ════════════════════════════════════════════════════════════
 * CAPA 2 — TOKEN BUCKET (lógica original adaptada para ip_key_t)
 * ════════════════════════════════════════════════════════════ */

/* Número máximo de reintentos CAS antes de rendirse (acota el loop para el verificador eBPF) */
#define CAS_MAX_RETRIES 8

static __always_inline int enforce_token_bucket(ip_key_t src_ip, __u64 now)
{
    struct custom_token_bucket  new_bucket = {0};
    struct custom_token_bucket *bucket;
    __u64 cost = (__u64)1 * TOKEN_SCALE;

    bucket = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (!bucket) {
        /* Primera vez que vemos esta IP: inicializar cubo lleno */
        new_bucket.tokens      = BURST_SIZE * TOKEN_SCALE;
        new_bucket.last_refill = now;
        new_bucket.burst_size  = BURST_SIZE;
        new_bucket.refill_rate = REFILL_RATE_PPS * TOKEN_SCALE;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_bucket, BPF_ANY);
        return XDP_PASS;
    }

    /* ── Recarga: solo la CPU que gana el CAS sobre last_refill aplica el
     * incremento de tokens (evita que varias CPUs sumen el mismo refill). ── */
    __u64 old_refill = bucket->last_refill;
    __u64 elapsed_ns = (now > old_refill) ? (now - old_refill) : 0;
    __u64 elapsed_seconds = elapsed_ns / 1000000000ULL;

    if (elapsed_seconds > 0 &&
        __sync_bool_compare_and_swap(&bucket->last_refill, old_refill, now)) {

        __u64 tokens_to_add = elapsed_seconds * bucket->refill_rate;
        __u64 max_tokens    = (__u64)bucket->burst_size * TOKEN_SCALE;

        #pragma unroll
        for (int i = 0; i < CAS_MAX_RETRIES; i++) {
            __u64 cur = bucket->tokens;
            __u64 new_tokens = cur + tokens_to_add;
            if (new_tokens > max_tokens)
                new_tokens = max_tokens;
            if (__sync_bool_compare_and_swap(&bucket->tokens, cur, new_tokens))
                break;
        }
    }

    /* ── Gasto: cada paquete intenta descontar `cost` tokens de forma atómica.
     * Si dos CPUs compiten, una gana el CAS y la otra reintenta sobre el valor
     * fresco — nunca se puede "gastar" el mismo token dos veces. ── */
    #pragma unroll
    for (int i = 0; i < CAS_MAX_RETRIES; i++) {
        __u64 cur = bucket->tokens;
        if (cur < cost)
            return XDP_DROP;
        if (__sync_bool_compare_and_swap(&bucket->tokens, cur, cur - cost))
            return XDP_PASS;
    }

    /* No se pudo confirmar el gasto tras varios reintentos bajo alta contención:
     * por seguridad, descartar en vez de dejar pasar sin contabilizar. */
    return XDP_DROP;
}


/* ════════════════════════════════════════════════════════════
 * CAPA 3 — RECOLECCIÓN DE ESTADÍSTICAS (adaptada para ip_key_t y L4 ptr)
 * ════════════════════════════════════════════════════════════ */

static __always_inline void update_ip_stats(ip_key_t src_ip,
                                             __u8  proto,
                                             __u32 pkt_len,
                                             __u64 now,
                                             int   tb_dropped,
                                             void *l4_ptr,
                                             void *data_end)
{
    struct ip_stats *s = bpf_map_lookup_elem(&ip_stats_map, &src_ip);

    if (!s) {
        /* IP nueva: crear entrada inicial */
        struct ip_stats new_s = {};
        new_s.pkt_count    = 1;
        new_s.byte_count   = pkt_len;
        new_s.first_seen_ns= now;
        new_s.last_seen_ns = now;
        new_s.tb_drops     = tb_dropped ? 1 : 0;

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)l4_ptr;
            if ((void *)(tcph + 1) <= data_end) {
                if (tcph->syn)
                    new_s.syn_count = 1;
                /* Solo SYN puro (SYN=1, ACK=0) cuenta como "intento de
                 * conexión a un puerto nuevo" — la firma real de un escaneo
                 * de puertos. Un paquete de respuesta a una conexión que
                 * ESTE host inició (ej. la respuesta de un servidor HTTPS
                 * externo) siempre lleva ACK=1 y su "puerto destino" es un
                 * puerto efímero local distinto por cada conexión saliente
                 * nueva — sin este filtro, cada charla con una API externa
                 * hacía crecer unique_dports como si el servidor remoto
                 * estuviera escaneando puertos de este host. */
                if (tcph->syn && !tcph->ack)
                    new_s.dport_bitmap = 1ULL << (bpf_ntohs(tcph->dest) % 64);
            }
        } else if (proto == IPPROTO_UDP) {
            new_s.udp_count = 1;
        } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
            new_s.icmp_count = 1;
        }

        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_s, BPF_ANY);
        return;
    }

    /* IP conocida: proteger con spinlock TODA la secuencia "chequear ventana
     * → resetear si corresponde → incrementar" para una única IP. Antes el
     * CAS solo cubría first_seen_ns; los otros 7 campos se reseteaban
     * secuencialmente sin lock, y un paquete concurrente en otra CPU podía
     * incrementar un campo ya reseteado mientras otro seguía con el valor de
     * la ventana anterior (stats corruptas, ej. byte_count > 0 con
     * pkt_count == 0). Dentro de la sección crítica solo hay accesos directos
     * a memoria (sin llamadas a otros helpers de BPF), como exige el
     * verificador para bpf_spin_lock. */
    __u64 iat;

    bpf_spin_lock(&s->lock);

    iat = (now > s->last_seen_ns) ? (now - s->last_seen_ns) : 0;

    if ((now - s->first_seen_ns) > WINDOW_NS) {
        s->first_seen_ns = now;
        s->pkt_count     = 0;
        s->byte_count    = 0;
        s->syn_count     = 0;
        s->udp_count     = 0;
        s->icmp_count    = 0;
        s->dport_bitmap  = 0;
        s->iat_sum_ns    = 0;
        s->tb_drops      = 0;
        iat = 0; /* el iat calculado contra la ventana anterior ya no aplica */
    }

    s->pkt_count  += 1;
    s->byte_count += pkt_len;
    s->iat_sum_ns += iat;
    s->last_seen_ns = now;

    if (tb_dropped)
        s->tb_drops += 1;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)l4_ptr;
        if ((void *)(tcph + 1) <= data_end) {
            if (tcph->syn)
                s->syn_count += 1;
            /* Ver comentario equivalente en la rama "IP nueva" más arriba:
             * solo SYN puro (SYN=1, ACK=0) cuenta como puerto nuevo
             * "sondeado" — excluye el tráfico de respuesta legítimo a
             * conexiones salientes que este host ya inició. */
            if (tcph->syn && !tcph->ack)
                s->dport_bitmap |= 1ULL << (bpf_ntohs(tcph->dest) % 64);
        }
    } else if (proto == IPPROTO_UDP) {
        s->udp_count += 1;
    } else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        s->icmp_count += 1;
    }

    bpf_spin_unlock(&s->lock);
}


/* ════════════════════════════════════════════════════════════
 * FASE 0 — LÍNEA BASE GLOBAL (no participa en el veredicto)
 * ════════════════════════════════════════════════════════════ */

static __always_inline void update_baseline(__u8 proto, __u32 pkt_len,
                                             void *l4_ptr, void *data_end)
{
    __u32 key = 0;
    struct baseline_stats *b = bpf_map_lookup_elem(&baseline_map, &key);
    if (!b)
        return;

    __sync_fetch_and_add(&b->total_pkts, 1);
    __sync_fetch_and_add(&b->total_bytes, pkt_len);

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)l4_ptr;
        if ((void *)(tcph + 1) <= data_end && bpf_ntohs(tcph->dest) == 443) {
            __sync_fetch_and_add(&b->tcp443_pkts, 1);
            __sync_fetch_and_add(&b->tcp443_bytes, pkt_len);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)l4_ptr;
        if ((void *)(udph + 1) <= data_end && bpf_ntohs(udph->dest) == 443) {
            __sync_fetch_and_add(&b->udp443_pkts, 1);
            __sync_fetch_and_add(&b->udp443_bytes, pkt_len);
        }
    }
}

/* ════════════════════════════════════════════════════════════
 * FASE 1 — HELPER DE TRIAJE
 * ════════════════════════════════════════════════════════════ */

/* Defensa en profundidad para CAPA 4: en producción el steering de hardware
 * (ethtool ntuple) ya garantiza que solo el tráfico de los puertos
 * inspeccionados (TCP/UDP:443 desde Fase 1; TCP:80 desde Fase 4) aterriza
 * en la cola de inspección, así que en teoría bastaría con mirar
 * ctx->rx_queue_index. Pero el riesgo R6 (documentado en MANUAL_TECNICO.md:
 * RSS puede saturar/desviar la cola de inspección si las reglas ntuple
 * quedan inconsistentes en el firmware) es real, y un veth/NIC de una sola
 * cola en desarrollo hace que ctx->rx_queue_index == 0 sea cierto para TODO
 * el tráfico, no solo el de estos puertos (confirmado con
 * tests/test_af_xdp_redirect.py en una máquina real: sin este chequeo,
 * tráfico a puertos arbitrarios también se redirigía). Chequear el puerto
 * acá, además de la cola, evita mandar tráfico que no nos interesa por el
 * viaje de ida y vuelta a userspace si el hardware alguna vez falla o no
 * está presente.
 *
 * Fase 4: se acepta también TCP dst-port 80 (HTTP plano — materia prima
 * real para el reensamblado + filesig de Fase 3). Deliberadamente NO se
 * acepta UDP:80 (HTTP corre sobre TCP); UDP:443 se mantiene porque es
 * tráfico QUIC/DTLS ya contemplado desde Fase 1.
 *
 * Fase SMB (§14), Fase D: TCP:445 se acepta en AMBAS direcciones
 * (dst-port O src-port 445) — a diferencia de 443/80, donde solo hace
 * falta ver al cliente (JA4/HTTP-request-como-contenido), el parser SMB2
 * propio (src/smb_parser.h) necesita también las RESPUESTAS del servidor
 * para extraer FileId (CREATE) y Data (READ). Esta es la única excepción
 * al criterio "solo dst-port" del resto de esta función — documentado acá
 * y en MANUAL_TECNICO.md §14.4/§14.6. Igual que con 80/443, la regla
 * ntuple real que dirige tráfico a esta cola vive fuera de este repo
 * (operativa, ver el comentario de R6 arriba); para 445 esa regla
 * operativa también necesita cubrir src-port 445, no solo dst-port. */
static __always_inline int is_inspected_port(__u8 proto, void *l4_ptr, void *data_end)
{
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)l4_ptr;
        if ((void *)(tcph + 1) > data_end)
            return 0;
        __u16 sport = bpf_ntohs(tcph->source);
        __u16 dport = bpf_ntohs(tcph->dest);
        return dport == 443 || dport == 80 || dport == 445 || sport == 445;
    }
    if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)l4_ptr;
        return (void *)(udph + 1) <= data_end && bpf_ntohs(udph->dest) == 443;
    }
    return 0;
}


/* ════════════════════════════════════════════════════════════
 * PROGRAMA PRINCIPAL XDP
 * ════════════════════════════════════════════════════════════ */

SEC("xdp")
int xdp_ddos_guardian(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Parse Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    ip_key_t src_ip = {};
    __u8 proto = 0;
    void *l4_ptr = NULL;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        /* ── Parse IPv4 ── */
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(&src_ip.ip[0], &iph->saddr, 4);
        src_ip.is_v6 = 0;
        proto = iph->protocol;

        /* IHL real (puede incluir opciones IPv4, mínimo 5 = 20 bytes sin opciones).
         * Si no se respeta, un atacante puede desalinear el parseo del header L4
         * agregando opciones y ensuciar las features sin que nada falle. */
        __u8 ihl = iph->ihl;
        if (ihl < 5)
            ihl = 5;
        void *l4_candidate = (void *)iph + (ihl * 4);
        if (l4_candidate > data_end)
            return XDP_PASS;
        l4_ptr = l4_candidate;

    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        /* ── Parse IPv6 ── */
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(src_ip.ip, &ip6h->saddr, 16);
        src_ip.is_v6 = 1;

        /* Caminar la cadena de extension headers (Hop-by-Hop, Destination
         * Options, Routing, Fragment) hasta encontrar el L4 real, en vez de
         * asumir que viene pegado al header fijo de 40 bytes. Acotado a un
         * número fijo de saltos para que el verificador acepte el loop. */
        __u8  nexthdr = ip6h->nexthdr;
        void *cursor  = (void *)(ip6h + 1);
        l4_ptr = NULL;

        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP || nexthdr == IPPROTO_ICMPV6) {
                proto  = nexthdr;
                l4_ptr = cursor;
                break;
            }
            /* 0=Hop-by-Hop, 43=Routing, 44=Fragment, 60=Destination Options:
             * comparten (o se aproximan a) el preámbulo [nexthdr, hdrlen]. Cualquier
             * otro valor (AH, ESP, desconocido) detiene la caminata de forma segura. */
            if (nexthdr != 0 && nexthdr != 43 && nexthdr != 44 && nexthdr != 60)
                break;

            struct { __u8 nexthdr; __u8 hdrlen; } *opt = cursor;
            if ((void *)(opt + 1) > data_end)
                return XDP_PASS;

            __u32 ext_len = (nexthdr == 44) ? 8 : ((__u32)opt->hdrlen + 1) * 8;
            nexthdr = opt->nexthdr;
            cursor  = cursor + ext_len;
            if (cursor > data_end)
                return XDP_PASS;
        }
        if (!l4_ptr || l4_ptr > data_end)
            return XDP_PASS;
    } else {
        return XDP_PASS; /* Ignorar tráfico no IPv4/IPv6 */
    }

    __u32 pkt_len = (data_end - data);
    __u64 now     = bpf_ktime_get_ns();

    /* Fase 0: cuenta el 100% del tráfico que llega hasta aquí, antes de
     * cualquier veredicto (whitelist/block/token-bucket). No condiciona
     * ningún DROP/PASS. */
    update_baseline(proto, pkt_len, l4_ptr, data_end);

    /* ════════════════════════════════════════════
     * CAPA 0 — Whitelist (Lista Blanca Absoluta)
     * Si la IP está en la lista blanca → PASS inmediato
     * sin consultar bloqueos ni gastar tokens del bucket.
     * ════════════════════════════════════════════ */
    __u8 *whitelisted = bpf_map_lookup_elem(&whitelist_map, &src_ip);
    if (whitelisted && *whitelisted == 1) {
        return XDP_PASS;
    }

    /* ════════════════════════════════════════════
     * CAPA 1 — Bloqueo duro por XGBoost (fast-path)
     * Si el predictor C++ marcó esta IP → DROP inmediato
     * sin pasar por token bucket ni actualizar stats.
     * ════════════════════════════════════════════ */
    block_val_t *blocked = bpf_map_lookup_elem(&block_map, &src_ip);
    if (blocked && *blocked == 1) {
        /* Contabilizar en drop_stats */
        __u32 key  = 0;
        __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_DROP;
    }

    /* ════════════════════════════════════════════
     * CAPA 2 — Token Bucket (tu lógica original)
     * Red de seguridad mientras XGBoost aún no ha
     * tomado una decisión sobre esta IP.
     * ════════════════════════════════════════════ */
    int tb_action = enforce_token_bucket(src_ip, now);

    if (tb_action == XDP_DROP) {
        __u32 key  = 0;
        __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        /* Registrar el drop en stats para que XGBoost lo vea como señal */
        update_ip_stats(src_ip, proto, pkt_len, now, 1, l4_ptr, data_end);
        return XDP_DROP;
    }

    /* ════════════════════════════════════════════
     * CAPA 3 — Actualizar stats para XGBoost
     * Solo se ejecuta si el paquete pasa ambas capas.
     * ════════════════════════════════════════════ */
    update_ip_stats(src_ip, proto, pkt_len, now, 0, l4_ptr, data_end);

    /* ════════════════════════════════════════════
     * CAPA 4 — Triaje Fase 1 (AF_XDP propio)
     * Solo llega aquí tráfico que ya pasó intacto el veredicto
     * volumétrico (CAPA 0-3).
     *
     * Segundo bug encontrado 2026-08-05 (más profundo que el de
     * rx_queue_index, ya corregido antes): este appliance está desplegado
     * como bridge transparente de 2 puertos (enp1s0 = uplink al gateway,
     * enp3s0 = hacia el AP de la LAN, unidos en br0 — ver
     * scripts/hawkeye_bridge_slaves.sh). El programa estaba adjunto a
     * br0 (el master), pero un bridge Linux NO vuelve a invocar el hook
     * de recepción del master para tráfico que solo está siendo
     * FORWARDEADO entre sus esclavos — eso pasa enteramente dentro del
     * procesamiento de red del esclavo que lo recibió, sin pasar de
     * nuevo por netif_receive_skb en br0. Confirmado empíricamente:
     * baseline_map (Fase 0, incondicional, antes de CUALQUIER veredicto)
     * mostraba tcp443_pkts=0/udp443_pkts=0 con miles de paquetes
     * contados en total — el tráfico 443 real (cliente LAN → servidor
     * remoto) jamás llegaba al programa. Lo único que SÍ veía br0 era
     * tráfico entregado localmente (broadcast/multicast/ARP/ND), que es
     * lo que aparecía en los logs del DDoS Guardian.
     *
     * Fix: predictor.cpp ahora adjunta este mismo programa a CADA
     * interfaz física del bridge por separado (ver load_bpf()), así que
     * el tráfico forwardeado SÍ dispara el hook (como ingreso genuino en
     * la física que lo recibió). Como bpf_redirect_map hacia un XSKMAP
     * exige que el socket destino esté bindeado a la MISMA interfaz de
     * ingreso, no alcanza un slot fijo — hay que resolver, para el
     * ifindex de ESTE paquete, cuál es su slot en xsks_map
     * (ifindex_slot, poblado por setup_triage()). Si no hay entrada
     * (interfaz sin AF_XDP configurado) el tráfico sigue XDP_PASS normal.
     *
     * IMPORTANTE (ver af_xdp_consumer.cpp): como este appliance es
     * inline y no un tap pasivo, bpf_redirect_map saca el frame del
     * camino normal del kernel — af_xdp_consumer.cpp es responsable de
     * retransmitirlo por la interfaz correcta (la OTRA física del
     * bridge) para no cortar la conectividad real. */
    capa4_dbg_inc(0);
    __u32 ifindex = ctx->ingress_ifindex;
    __u32 *slot = bpf_map_lookup_elem(&ifindex_slot, &ifindex);
    if (slot) {
        capa4_dbg_inc(2); /* ifindex_slot con entrada para esta interfaz */
        /* Diagnóstico: qué cola RX de hardware REAL reporta el kernel para
         * este paquete — nunca se midió directo, solo se asumió 0 por el
         * "combined 1" de hawkeye_nic_queues.sh. */
        if (ctx->rx_queue_index == 0)
            capa4_dbg_inc(15);
        else if (ctx->rx_queue_index == 1)
            capa4_dbg_inc(16);
        else if (ctx->rx_queue_index == 2)
            capa4_dbg_inc(17);
        else if (ctx->rx_queue_index == 3)
            capa4_dbg_inc(18);
        else
            capa4_dbg_inc(19);
        if (*slot == 0)
            capa4_dbg_inc(10);
        else if (*slot == 1)
            capa4_dbg_inc(11);
        else
            capa4_dbg_inc(12); /* valor inesperado (>=2) */
        if (proto == IPPROTO_TCP) {
            capa4_dbg_inc(3); /* proto TCP */
            struct tcphdr *tcph = (struct tcphdr *)l4_ptr;
            if ((void *)(tcph + 1) <= data_end) {
                __u16 dport = bpf_ntohs(tcph->dest);
                if (dport == 443)
                    capa4_dbg_inc(4);
                else if (dport == 80)
                    capa4_dbg_inc(5);
                else if (dport == 445)
                    capa4_dbg_inc(6);
            }
        } else if (proto == IPPROTO_UDP) {
            capa4_dbg_inc(7); /* proto UDP */
        }

        if (is_inspected_port(proto, l4_ptr, data_end)) {
            capa4_dbg_inc(1);
            __u32 xsk_key = 0; /* cada mapa dedicado tiene 1 sola entrada */
            void *xsk_entry;
            long ret;

            if (*slot == 0) {
                xsk_entry = bpf_map_lookup_elem(&xsks_map_a, &xsk_key);
                capa4_dbg_inc(xsk_entry ? 13 : 14);
                ret = bpf_redirect_map(&xsks_map_a, 0, XDP_PASS);
            } else if (*slot == 1) {
                xsk_entry = bpf_map_lookup_elem(&xsks_map_b, &xsk_key);
                capa4_dbg_inc(xsk_entry ? 13 : 14);
                ret = bpf_redirect_map(&xsks_map_b, 0, XDP_PASS);
            } else {
                /* Solo soportamos 2 interfaces (bridge de 2 puertos) —
                 * cualquier otro slot es un estado inesperado, seguir
                 * XDP_PASS normal en vez de arriesgar un redirect a ciegas. */
                return XDP_PASS;
            }

            if (ret == XDP_REDIRECT)
                capa4_dbg_inc(8);
            else
                capa4_dbg_inc(9);
            return ret;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
