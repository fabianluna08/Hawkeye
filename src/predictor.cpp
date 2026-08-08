/* src/predictor.cpp
 *
 * Predictor en tiempo real — DDoS Guardian
 *
 * Lee ip_stats_map (escrito por XDP cada paquete), construye el vector
 * de features, hace inferencia con XGBoost C API y, si P(ataque) ≥ umbral,
 * escribe en block_map para que XDP bloquee la IP en el siguiente paquete.
 *
 * CAMBIOS v2:
 *   - N_FEATURES 8 → 9: se agrega unique_dports en feat[7].
 *   - tb_drop_ratio pasa de feat[7] a feat[8].
 *   - Orden de features DEBE coincidir con FEATURE_COLS en train.py:
 *       [0] pps  [1] bps  [2] mean_iat_ms  [3] syn_ratio
 *       [4] udp_ratio  [5] icmp_ratio  [6] pkt_count
 *       [7] unique_dports  [8] tb_drop_ratio
 *
 * CAMBIOS v3 (rendimiento bajo ataque masivo, muchas IPs concurrentes):
 *   - Inferencia por lotes: un solo DMatrix N×9 y una sola llamada a
 *     XGBoosterPredictFromDMatrix por ciclo de poll, en vez de crear/destruir
 *     un DMatrix 1×9 por IP.
 *   - Cache de "ultima evaluacion" (first_seen_ns + pkt_count) por IP: si no
 *     llego ningun paquete nuevo desde el ciclo anterior, se salta la
 *     inferencia para esa IP en este ciclo (el poll es de 50ms, la ventana
 *     del kernel es de 1s — sin esto se re-evalua lo mismo hasta 20x/seg).
 *
 * CAMBIOS v4 (falsos positivos con trafico real de navegacion/APIs):
 *   - Confirmacion por sospecha sostenida (hysteresis): una sola evaluacion
 *     de 50ms con P≥umbral ya NO bloquea. Se exige que la IP acumule
 *     CONFIRM_HITS evaluaciones consecutivas sospechosas (cada una con
 *     paquetes nuevos, garantizado por el cache last_eval) que ademas
 *     abarquen al menos CONFIRM_SPAN_MS de tiempo real. Motivo: el modelo
 *     (entrenado con CICDDoS2019 + muestras sinteticas cuyo trafico benigno
 *     solo cubre pps 1-20) da P=0.5-0.83 a rafagas cortas y legitimas de
 *     respuesta HTTP/HTTPS/QUIC (pps 25-1000 durante <1s). Un ataque real
 *     sostiene el patron durante segundos y cruza varias ventanas de 1s del
 *     kernel; una rafaga legitima de respuesta vive dentro de una sola
 *     ventana y se corta antes de poder confirmarse. La racha solo se
 *     resetea por staleness (mas de SUSPICION_STALE_MS sin evaluaciones
 *     sospechosas): asi dos rafagas legitimas separadas en el tiempo no se
 *     suman entre si. Una evaluacion benigna aislada NO corta la racha a
 *     proposito: al resetearse la ventana de 1s del kernel las stats quedan
 *     sub-muestreadas y el modelo puntua bajo durante los primeros ~250ms
 *     de cada ventana, incluso en pleno flood — un reset duro haria que un
 *     ataque real nunca acumulara 1.5s de racha (verificado con el modelo
 *     real en scripts/verify_block_logic.py).
 *   - MIN_PKTS 10 → 20: con 10 paquetes el pps estimado sobre decenas de ms
 *     es puro ruido (10 pkts en 47ms → "213 pps") y varios falsos positivos
 *     reales cayeron exactamente en ese piso. Un flood real junta 20
 *     paquetes en milisegundos; mientras tanto el Token Bucket del kernel
 *     (Capa 2) ya limita a cualquier IP no evaluada a 100 pps.
 *
 * CAMBIOS v5 (captura de datos reales para reentrenar el modelo):
 *   - El modelo se entrenó con CICDDoS2019 + sintético, cuyo tráfico benigno
 *     no cubre los patrones reales que causaron los falsos positivos de v4
 *     (ver CAMBIOS v4). El arreglo de raíz es reentrenar con tráfico
 *     benigno REAL, no solo ajustar umbrales/hysteresis.
 *   - HAWKEYE_CAPTURE_TRAINING_DATA=1 activa la captura: cada ~
 *     CAPTURE_SAMPLE_INTERVAL_MS por IP evaluada, se apendea una fila con
 *     las 9 features + label a training_samples.jsonl (independiente del
 *     agente Python/socket — se escribe directo desde acá para no meter
 *     datos de alta frecuencia por el mismo canal que dispara SHAP+ChromaDB
 *     en agent.py, pensado para alertas reales, no para telemetría masiva).
 *   - Label por default: 0 (benigno) si no se confirmó bloqueo en ese ciclo,
 *     1 si sí. HAWKEYE_CAPTURE_LABEL=0|1, si está seteada, fuerza ESE label
 *     para TODAS las filas capturadas en la corrida — pensado para ventanas
 *     controladas donde vos sabés con certeza qué es (ej. corriendo
 *     scripts/hawkeye_stress_test.py contra tu propia red: forzás label=1
 *     sin depender de si la hysteresis ya confirmó o no en cada ventana).
 *   - Ver python/online_trainer.py:train_from_capture() para consumir este
 *     archivo y reentrenar.
 *
 * Compilar: cmake -B build -S . && cmake --build build
 * Uso:      sudo ./build/predictor eth0 modelo.json
 */

#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <cmath>
#include <cstdio>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_SKB_MODE */
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <grp.h>
#include <cstdlib>

/* libbpf CO-RE (kernel ≥ 5.2 con BTF) */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* XGBoost C API ≥ 2.0 */
#include <xgboost/c_api.h>

/* Structs compartidos con el programa BPF */
#include "../kern/xdp_common.h"

#include <sys/stat.h>
#include <sys/types.h>

/* ════════════════════════════════════════════════════════════
 * MACRO DE ERRORES XGBOOST
 * ════════════════════════════════════════════════════════════ */
#define safe_xgb(call)                                               \
    do {                                                             \
        int _rc = (call);                                            \
        if (_rc != 0) {                                              \
            fprintf(stderr, "[XGB] %s:%d  %s\n  → %s\n",           \
                    __FILE__, __LINE__, #call, XGBGetLastError());   \
            std::exit(1);                                            \
        }                                                            \
    } while (0)

/* ════════════════════════════════════════════════════════════
 * CONFIGURACIÓN
 * ════════════════════════════════════════════════════════════ */

/* IMPORTANTE: debe coincidir exactamente con el orden en train.py */
static constexpr int    N_FEATURES        = 9;   /* +unique_dports respecto a v1 */
static constexpr double DECISION_THRESH   = 0.5;
static constexpr int    POLL_INTERVAL_MS  = 50;
static constexpr int    MIN_PKTS          = 20;  /* Ignorar IPs con muy pocos pkts:
                                                  * con menos de 20 el pps estimado
                                                  * es ruido y <20 pps sostenidos no
                                                  * son un DDoS (el Token Bucket ya
                                                  * limita a 100 pps por IP). */
static constexpr int    BLOCK_DURATION_S  = 60;

/* ── Confirmacion por sospecha sostenida (hysteresis, v4) ──
 * Bloquear solo si la IP acumula CONFIRM_HITS evaluaciones consecutivas con
 * P≥umbral (cada una implica paquetes nuevos) y la racha abarca al menos
 * CONFIRM_SPAN_MS. Con la ventana del kernel de 1s (WINDOW_NS), exigir 1.5s
 * fuerza a que el patron sospechoso cruce un limite de ventana: una rafaga
 * legitima de respuesta (HTTP/streaming) vive dentro de una sola ventana y
 * nunca llega; un flood real confirma en ~1.5-2.5s (y mientras tanto la
 * Capa 2 del kernel lo mantiene acotado a 100 pps). Si entre dos
 * evaluaciones sospechosas pasan mas de SUSPICION_STALE_MS, la racha se
 * resetea: dos rafagas legitimas separadas en el tiempo no deben sumarse
 * entre si. Una evaluacion benigna aislada no resetea (ver CAMBIOS v4). */
static constexpr int    CONFIRM_HITS       = 3;
static constexpr int    CONFIRM_SPAN_MS    = 1500;
static constexpr int    SUSPICION_STALE_MS = 2000;

/* Debe coincidir con AGENT_SOCK en python/agent.py: un subdirectorio de /tmp
 * creado y bloqueado en 0700 por el agente (no un archivo suelto y predecible
 * directamente en /tmp, que cualquier usuario local podría adelantarse a crear). */
static constexpr const char *AGENT_SOCK  = "/tmp/hawkeye-agent-ipc/ddos_agent.sock";

/* ── Captura de datos para reentrenar (v5, ver CAMBIOS arriba) ──
 * Relativo al cwd, igual que modelo.json/xdp_kern.o (se corre desde la raíz
 * del repo: `sudo ./build/predictor <iface> modelo.json`). */
static constexpr const char *TRAINING_CAPTURE_PATH   = "training_samples.jsonl";
static constexpr int         CAPTURE_SAMPLE_INTERVAL_MS = 2000;

/* ── Fase 1: triaje AF_XDP propio (opt-in, ver setup_triage()) ──
 * Ruta bajo bpffs donde se pinean xsks_map_a/b para que
 * src/af_xdp_consumer.cpp (proceso separado) los abra por su cuenta.
 * /sys/fs/bpf/hawkeye/ debe montarse antes de pinear (típicamente ya está
 * montado por systemd en distros modernas; si no, "mount -t bpf bpf
 * /sys/fs/bpf"). Dos mapas dedicados, no uno compartido — ver comentario
 * de xsks_map_a/xsks_map_b en kern/xdp_kern.c (bug 2026-08-05). */
static constexpr const char *TRIAGE_PIN_DIR       = "/sys/fs/bpf/hawkeye";
static constexpr const char *XSKS_MAP_A_PIN_PATH  = "/sys/fs/bpf/hawkeye/xsks_map_a";
static constexpr const char *XSKS_MAP_B_PIN_PATH  = "/sys/fs/bpf/hawkeye/xsks_map_b";

/* ════════════════════════════════════════════════════════════
 * SEÑAL DE SALIDA LIMPIA
 * ════════════════════════════════════════════════════════════ */
static std::atomic<bool> g_running{true};
static void sig_handler(int) { g_running = false; }

/* ════════════════════════════════════════════════════════════
 * UTILIDADES
 * ════════════════════════════════════════════════════════════ */
inline bool operator==(const ip_key_t &a, const ip_key_t &b) {
    if (a.is_v6 != b.is_v6) return false;
    if (a.is_v6) {
        return std::memcmp(a.ip, b.ip, 16) == 0;
    } else {
        return a.ip[0] == b.ip[0];
    }
}

struct ip_key_hash {
    std::size_t operator()(const ip_key_t &k) const {
        if (k.is_v6) {
            std::size_t h = 0;
            for (int i = 0; i < 4; ++i) {
                h ^= std::hash<uint32_t>{}(k.ip[i]) + 0x9e3779b9 + (h << 6) + (h >> 2);
            }
            return h;
        } else {
            return std::hash<uint32_t>{}(k.ip[0]);
        }
    }
};

static std::string ip_to_str(const ip_key_t &key) {
    char buf[INET6_ADDRSTRLEN];
    if (key.is_v6) {
        struct in6_addr addr;
        std::memcpy(&addr, key.ip, 16);
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    } else {
        struct in_addr addr;
        std::memcpy(&addr, &key.ip[0], 4);
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    }
    return buf;
}

static __u64 get_monotonic_ns() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }
    return 0;
}

/* Convierte ip_stats → vector de features para XGBoost.
 * Orden DEBE coincidir con FEATURE_COLS en train.py:
 *   [0] pps          [1] bps          [2] mean_iat_ms
 *   [3] syn_ratio    [4] udp_ratio    [5] icmp_ratio
 *   [6] pkt_count    [7] unique_dports [8] tb_drop_ratio   */
static void stats_to_features(const struct ip_stats &s,
                               float out[N_FEATURES])
{
    double elapsed_s = (s.last_seen_ns - s.first_seen_ns) / 1e9;
    if (elapsed_s < 0.001) elapsed_s = 0.001;

    double pps           = s.pkt_count  / elapsed_s;
    double bps           = s.byte_count / elapsed_s;
    double mean_iat_ms   = (s.pkt_count > 1)
        ? (s.iat_sum_ns / (double)(s.pkt_count - 1)) / 1e6 : 0.0;
    double syn_ratio     = s.pkt_count ? s.syn_count  / (double)s.pkt_count : 0.0;
    double udp_ratio     = s.pkt_count ? s.udp_count  / (double)s.pkt_count : 0.0;
    double icmp_ratio    = s.pkt_count ? s.icmp_count / (double)s.pkt_count : 0.0;
    double tb_drop_ratio = s.pkt_count
        ? s.tb_drops / (double)(s.pkt_count + s.tb_drops) : 0.0;

    out[0] = static_cast<float>(pps);
    out[1] = static_cast<float>(bps);
    out[2] = static_cast<float>(mean_iat_ms);
    out[3] = static_cast<float>(syn_ratio);
    out[4] = static_cast<float>(udp_ratio);
    out[5] = static_cast<float>(icmp_ratio);
    out[6] = static_cast<float>(s.pkt_count);
    out[7] = static_cast<float>(__builtin_popcountll(s.dport_bitmap));  /* puertos destino únicos (aprox.) */
    out[8] = static_cast<float>(tb_drop_ratio);    /* ← era out[7] en v1        */
}

/* Envía alerta JSON al agente Python (no bloqueante) */
static void alert_agent(const std::string &json) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        fprintf(stderr, "[alert_agent] No se pudo crear el socket: %s\n", strerror(errno));
        return;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AGENT_SOCK, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[alert_agent] No se pudo conectar a %s: %s (¿el agente Python está corriendo?)\n",
                AGENT_SOCK, strerror(errno));
        close(fd);
        return;
    }

    ssize_t written = write(fd, json.c_str(), json.size());
    if (written < 0) {
        fprintf(stderr, "[alert_agent] Error escribiendo la alerta: %s\n", strerror(errno));
    } else if ((size_t)written != json.size()) {
        fprintf(stderr, "[alert_agent] Escritura parcial: %zd/%zu bytes\n", written, json.size());
    }
    close(fd);
}

/* Construye JSON de alerta */
static std::string make_alert_json(const ip_key_t &ip,
                                   const float feat[N_FEATURES],
                                   double prob)
{
    std::ostringstream o;
    o << "{"
      << R"("ip":")"           << ip_to_str(ip) << R"(",)"
      << R"("prob":)"          << prob          << ","
      << R"("pps":)"           << feat[0]       << ","
      << R"("bps":)"           << feat[1]       << ","
      << R"("mean_iat_ms":)"   << feat[2]       << ","
      << R"("syn_ratio":)"     << feat[3]       << ","
      << R"("udp_ratio":)"     << feat[4]       << ","
      << R"("icmp_ratio":)"    << feat[5]       << ","
      << R"("pkt_count":)"     << feat[6]       << ","
      << R"("unique_dports":)" << feat[7]       << ","
      << R"("tb_drop_ratio":)" << feat[8]
      << "}\n";
    return o.str();
}

/* Apendea una fila de entrenamiento a TRAINING_CAPTURE_PATH (v5). Columnas
 * en el mismo orden que FEATURE_COLS en python/online_trainer.py; el campo
 * "label" es lo que hace que esto sirva para reentrenar (0=benigno,
 * 1=ataque) — ver train_from_capture(). No pasa por el socket del agente
 * Python a propósito: esto puede escribir varias filas por segundo bajo
 * tráfico activo, y el otro extremo del socket (agent.py) hace SHAP +
 * ChromaDB por cada mensaje recibido, pensado para alertas reales
 * infrecuentes, no para telemetría de entrenamiento de alto volumen. */
static void capture_training_sample(const ip_key_t &ip,
                                     const float feat[N_FEATURES],
                                     int label)
{
    std::ostringstream o;
    o << "{"
      << R"("ip":")"           << ip_to_str(ip) << R"(",)"
      << R"("pps":)"           << feat[0]       << ","
      << R"("bps":)"           << feat[1]       << ","
      << R"("mean_iat_ms":)"   << feat[2]       << ","
      << R"("syn_ratio":)"     << feat[3]       << ","
      << R"("udp_ratio":)"     << feat[4]       << ","
      << R"("icmp_ratio":)"    << feat[5]       << ","
      << R"("pkt_count":)"     << feat[6]       << ","
      << R"("unique_dports":)" << feat[7]       << ","
      << R"("tb_drop_ratio":)" << feat[8]       << ","
      << R"("label":)"         << label
      << "}\n";

    std::ofstream f(TRAINING_CAPTURE_PATH, std::ios::app);
    if (f) {
        f << o.str();
    } else {
        fprintf(stderr, "[capture] No se pudo escribir en %s: %s\n",
                TRAINING_CAPTURE_PATH, strerror(errno));
    }
}

/* ════════════════════════════════════════════════════════════
 * CLASE PRINCIPAL
 * ════════════════════════════════════════════════════════════ */
class DDoSPredictor {
public:
    DDoSPredictor(const char *iface, const char *model_path)
        : iface_(iface)
    {
        /* Cargar y validar el modelo ANTES de adjuntar XDP: si el modelo falla
         * (archivo faltante, features incompatibles), safe_xgb() hace
         * std::exit(1) y nos saltamos el destructor — pero como todavía no
         * adjuntamos nada, no hay link XDP que se quede huérfano. */
        load_model(model_path);
        load_bpf(iface);

        /* Captura de datos para reentrenar (v5) — off por default, opt-in. */
        const char *cap_env = getenv("HAWKEYE_CAPTURE_TRAINING_DATA");
        capture_enabled_ = cap_env && (std::string(cap_env) == "1" ||
                                        std::string(cap_env) == "true");
        const char *label_env = getenv("HAWKEYE_CAPTURE_LABEL");
        if (label_env && (std::string(label_env) == "0" || std::string(label_env) == "1")) {
            capture_label_override_ = std::atoi(label_env);
        }
        if (capture_enabled_) {
            std::cout << "[*] Captura de datos de entrenamiento ACTIVA → "
                      << TRAINING_CAPTURE_PATH;
            if (capture_label_override_ >= 0) {
                std::cout << " (label forzado=" << capture_label_override_ << ")";
            }
            std::cout << "\n";
        }
    }

    ~DDoSPredictor() {
        if (booster_) XGBoosterFree(booster_);
        /* Desadjuntar con las MISMAS flags (SKB_MODE) que se usaron para
         * adjuntar — prog_fd=-1 remueve el programa de esa interfaz. */
        for (int ifindex : xdp_attached_ifindexes_)
            bpf_xdp_attach(ifindex, -1, XDP_FLAGS_SKB_MODE, nullptr);
        if (obj_) bpf_object__close(obj_);
    }

    void run() {
        std::cout << "[*] DDoS Guardian activo en " << iface_
                  << " — Umbral P(ataque)=" << DECISION_THRESH
                  << " — Ctrl+C para detener\n";

        /* IP → tiempo de expiración del bloqueo */
        std::unordered_map<ip_key_t,
            std::chrono::steady_clock::time_point, ip_key_hash> block_expiry;

        /* IP → (first_seen_ns, pkt_count) de la última vez que SÍ se evaluó
         * con XGBoost. Si en el ciclo actual ambos valores son idénticos,
         * no llegó ningún paquete nuevo desde entonces (mismo dato, mismo
         * resultado) y se salta la predicción para esa IP. Se compara por
         * delta de pkt_count (no "una vez por ventana de 1s") para no perder
         * detección si una IP arranca benigna y ataca a mitad de ventana. */
        std::unordered_map<ip_key_t,
            std::pair<__u64, __u64>, ip_key_hash> last_eval;

        /* IP → racha de evaluaciones sospechosas (P≥umbral) todavia no
         * confirmadas. Ver comentario de CONFIRM_HITS/CONFIRM_SPAN_MS. */
        struct suspicion_state {
            int hits = 0;
            std::chrono::steady_clock::time_point first_hit{};
            std::chrono::steady_clock::time_point last_hit{};
        };
        std::unordered_map<ip_key_t, suspicion_state, ip_key_hash> suspicion;

        /* IP → última vez que se apendeó una fila a training_samples.jsonl
         * (v5). Throttle a CAPTURE_SAMPLE_INTERVAL_MS por IP: sin esto, una
         * IP activa generaría una fila por cada evaluación (hasta 20/seg),
         * mucho más de lo que hace falta para juntar un dataset de
         * reentrenamiento representativo. */
        std::unordered_map<ip_key_t,
            std::chrono::steady_clock::time_point, ip_key_hash> last_capture;

        while (g_running) {
            auto now_tp = std::chrono::steady_clock::now();

            /* ── Desbloquear IPs expiradas ── */
            for (auto it = block_expiry.begin(); it != block_expiry.end(); ) {
                if (now_tp >= it->second) {
                    ip_key_t ip = it->first;
                    bpf_map_delete_elem(block_fd_, &ip);
                    std::cout << "[~] Desbloqueado: " << ip_to_str(ip) << "\n";
                    it = block_expiry.erase(it);
                } else {
                    ++it;
                }
            }

            /* ── Iterar ip_stats_map (escrito por XDP) ── */
            std::vector<ip_key_t>        keys_to_delete;
            std::vector<ip_key_t>        batch_keys;
            std::vector<float>           batch_feats;   /* flat, N_FEATURES por fila */
            std::vector<struct ip_stats> batch_stats;   /* para log/alerta post-predict */
            ip_key_t key, next_key;
            const void *key_ptr = nullptr;
            __u64 now_ns = get_monotonic_ns();

            while (bpf_map_get_next_key(stats_fd_, key_ptr, &next_key) == 0) {

                struct ip_stats s{};
                if (bpf_map_lookup_elem(stats_fd_, &next_key, &s) != 0) {
                    key = next_key;
                    key_ptr = &key;
                    continue;
                }

                /* Limpieza de IPs inactivas (ej: 5 segundos sin paquetes) */
                if (now_ns > s.last_seen_ns && (now_ns - s.last_seen_ns) > 5000000000ULL) {
                    keys_to_delete.push_back(next_key);
                    last_eval.erase(next_key);
                    suspicion.erase(next_key);
                    last_capture.erase(next_key);
                    key = next_key;
                    key_ptr = &key;
                    continue;
                }

                /* Filtrar IPs con muy pocos paquetes */
                if (s.pkt_count < (unsigned)MIN_PKTS) {
                    key = next_key;
                    key_ptr = &key;
                    continue;
                }

                /* Si no llegó ningún paquete nuevo desde la última vez que se
                 * evaluó esta IP (mismo first_seen_ns y mismo pkt_count), el
                 * resultado de XGBoost sería idéntico: saltar la inferencia. */
                auto cached = last_eval.find(next_key);
                if (cached != last_eval.end() &&
                    cached->second.first  == s.first_seen_ns &&
                    cached->second.second == s.pkt_count) {
                    key = next_key;
                    key_ptr = &key;
                    continue;
                }

                /* ── Acumular features para predicción por lotes ── */
                float feat[N_FEATURES];
                stats_to_features(s, feat);

                batch_keys.push_back(next_key);
                batch_feats.insert(batch_feats.end(), feat, feat + N_FEATURES);
                batch_stats.push_back(s);

                key = next_key;
                key_ptr = &key;
            }

            /* ── Predicción por lotes: un solo DMatrix + una sola llamada ── */
            if (!batch_keys.empty()) {
                std::vector<double> probs = predict_batch(batch_feats, batch_keys.size());

                for (size_t i = 0; i < batch_keys.size(); ++i) {
                    const ip_key_t        &next_key = batch_keys[i];
                    const struct ip_stats &s        = batch_stats[i];
                    const float           *feat     = &batch_feats[i * N_FEATURES];
                    double                  prob     = probs[i];

                    /* ── Decision con confirmacion sostenida (v4) ──
                     * Una evaluacion aislada con P≥umbral solo marca la IP
                     * como sospechosa; se bloquea recien cuando la racha de
                     * evaluaciones sospechosas consecutivas alcanza
                     * CONFIRM_HITS y abarca al menos CONFIRM_SPAN_MS. */
                    bool confirmed = false;
                    int  streak    = 0;
                    if (prob >= DECISION_THRESH) {
                        auto &sus = suspicion[next_key];
                        if (sus.hits > 0 &&
                            now_tp - sus.last_hit >
                                std::chrono::milliseconds(SUSPICION_STALE_MS)) {
                            /* Racha vieja: la sospecha no fue sostenida en el
                             * tiempo, arrancar de cero. */
                            sus.hits = 0;
                        }
                        if (sus.hits == 0)
                            sus.first_hit = now_tp;
                        sus.hits    += 1;
                        sus.last_hit = now_tp;
                        streak       = sus.hits;

                        confirmed = sus.hits >= CONFIRM_HITS &&
                            (now_tp - sus.first_hit) >=
                                std::chrono::milliseconds(CONFIRM_SPAN_MS);
                    } else {
                        /* Evaluacion benigna: NO corta la racha (el modelo
                         * puntua bajo en los primeros ~250ms de cada ventana
                         * de 1s del kernel, incluso durante un flood real —
                         * la racha muere solo por staleness). Si la racha ya
                         * esta vieja, limpiar la entrada para no acumular
                         * estado de flujos benignos de larga vida. */
                        auto it = suspicion.find(next_key);
                        if (it != suspicion.end() &&
                            now_tp - it->second.last_hit >
                                std::chrono::milliseconds(SUSPICION_STALE_MS)) {
                            suspicion.erase(it);
                        }
                    }

                    /* Log de debug: muestra score de todas las IPs evaluadas */
                    char status[48] = "";
                    if (confirmed) {
                        snprintf(status, sizeof(status), " ← BLOQUEADO");
                    } else if (streak > 0) {
                        snprintf(status, sizeof(status),
                                 " ← sospechosa (racha=%d)", streak);
                    }
                    fprintf(stderr,
                        "[DBG] IP=%-40s pkts=%4llu syn=%.2f dports=%4llu pps=%6.1f P=%.4f%s\n",
                        ip_to_str(next_key).c_str(),
                        (unsigned long long)s.pkt_count,
                        feat[3],   /* syn_ratio     */
                        (unsigned long long)__builtin_popcountll(s.dport_bitmap),
                        feat[0],   /* pps           */
                        prob,
                        status);

                    /* Captura de datos de entrenamiento (v5), opt-in y
                     * throtteada por IP — ver CAMBIOS v5 y
                     * CAPTURE_SAMPLE_INTERVAL_MS. Se captura tanto lo
                     * confirmado como lo benigno/sospechoso: el objetivo es
                     * juntar tráfico real (mayormente benigno) para el
                     * reentrenamiento, no solo bloqueos. */
                    if (capture_enabled_) {
                        auto cap_it = last_capture.find(next_key);
                        bool due = cap_it == last_capture.end() ||
                            (now_tp - cap_it->second) >=
                                std::chrono::milliseconds(CAPTURE_SAMPLE_INTERVAL_MS);
                        if (due) {
                            int label = (capture_label_override_ >= 0)
                                ? capture_label_override_
                                : (confirmed ? 1 : 0);
                            capture_training_sample(next_key, feat, label);
                            last_capture[next_key] = now_tp;
                        }
                    }

                    __u8 wl_flag = 0;
                    if (whitelist_fd_ >= 0 && bpf_map_lookup_elem(whitelist_fd_, &next_key, &wl_flag) == 0 && wl_flag == 1) {
                        /* Está en lista blanca → ignorar y limpiar de ip_stats_map */
                        keys_to_delete.push_back(next_key);
                        last_eval.erase(next_key);
                        suspicion.erase(next_key);
                        last_capture.erase(next_key);
                        continue;
                    }

                    if (confirmed) {
                        /* Marcar en block_map → XDP dropeará en microsegundos */
                        __u8 flag = 1;
                        bpf_map_update_elem(block_fd_, &next_key, &flag, BPF_ANY);
                        block_expiry[next_key] = now_tp +
                            std::chrono::seconds(BLOCK_DURATION_S);

                        /* Borrar de las estadísticas para no seguir evaluando por XGBoost inútilmente */
                        keys_to_delete.push_back(next_key);
                        last_eval.erase(next_key);
                        suspicion.erase(next_key);
                        last_capture.erase(next_key);

                        std::string alert = make_alert_json(next_key, feat, prob);
                        std::cout << "[!] BLOQUEADO: " << ip_to_str(next_key)
                                  << "  P=" << prob
                                  << "  PPS=" << feat[0]
                                  << "  dports=" << __builtin_popcountll(s.dport_bitmap)
                                  << "  syn_ratio=" << feat[3]
                                  << "  TB_drops=" << s.tb_drops << "\n";
                        alert_agent(alert);
                    } else {
                        /* No bloqueada (benigna o sospechosa sin confirmar):
                         * recordar qué se evaluó para saltar la próxima vez
                         * si no llega tráfico nuevo. La sospechosa sigue
                         * viva en ip_stats_map: si el patron persiste con
                         * paquetes nuevos, la racha crece y confirma. */
                        last_eval[next_key] = {s.first_seen_ns, s.pkt_count};
                    }
                }
            }

            /* Borrar de forma segura todas las IPs recolectadas */
            for (const ip_key_t &k : keys_to_delete) {
                bpf_map_delete_elem(stats_fd_, &k);
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(POLL_INTERVAL_MS));
        }

        std::cout << "[*] Salida limpia.\n";
    }

private:
    /* Separa "enp1s0,enp3s0" en {"enp1s0","enp3s0"}. Con un solo nombre
     * (sin comas) devuelve un vector de 1 elemento — despliegue de una
     * sola interfaz, comportamiento idéntico al de antes de esto. */
    static std::vector<std::string> split_ifaces(const char *arg) {
        std::vector<std::string> out;
        std::stringstream ss(arg);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            if (!tok.empty()) out.push_back(tok);
        }
        return out;
    }

    /* ── Carga el objeto BPF compilado y adjunta XDP a cada interfaz ── *
     * Acepta una LISTA de interfaces (bug encontrado 2026-08-05, ver
     * comentario largo de CAPA 4 en kern/xdp_kern.c): este appliance es
     * un bridge de 2 puertos físicos, y adjuntar el programa solo al
     * bridge master (br0) nunca ve tráfico genuinamente forwardeado
     * entre sus esclavos. Adjuntando el MISMO programa/objeto BPF ya
     * cargado a cada física por separado, todas comparten los mismos
     * mapas (block_map, ip_stats_map, xsks_map, etc.) — el veredicto
     * volumétrico y el bloqueo quedan unificados sin importar por cuál
     * entró el paquete. */
    void load_bpf(const char *iface_arg) {
        ifaces_ = split_ifaces(iface_arg);
        if (ifaces_.empty()) {
            fprintf(stderr, "[!] Ninguna interfaz válida en '%s'\n", iface_arg);
            std::exit(1);
        }

        obj_ = bpf_object__open("xdp_kern.o");
        if (!obj_) { perror("bpf_object__open"); std::exit(1); }

        if (bpf_object__load(obj_) != 0) {
            perror("bpf_object__load"); std::exit(1);
        }

        /* Obtener FDs de los tres mapas por nombre */
        auto get_fd = [&](const char *name) {
            auto *m = bpf_object__find_map_by_name(obj_, name);
            if (!m) {
                fprintf(stderr, "Mapa '%s' no encontrado en xdp_kern.o\n", name);
                std::exit(1);
            }
            return bpf_map__fd(m);
        };

        stats_fd_     = get_fd("ip_stats_map");
        block_fd_     = get_fd("block_map");
        whitelist_fd_ = get_fd("whitelist_map");
        /* rate_limit_map es solo para XDP, no lo necesitamos aquí */

        /* Limpiar mapas al arranque */
        wipe_map(stats_fd_, "ip_stats_map");
        wipe_map(block_fd_, "block_map");

        setup_triage();

        /* Adjuntar con BPF link (método moderno, kernel ≥ 5.7), una vez
         * por interfaz. Si alguna falla, se aborta (mejor no arrancar a
         * medias en un appliance inline: dejar una física del bridge sin
         * inspección rompería la simetría del relay en
         * af_xdp_consumer.cpp de forma silenciosa). */
        auto *prog = bpf_object__find_program_by_name(obj_, "xdp_ddos_guardian");
        if (!prog) {
            fprintf(stderr, "Programa 'xdp_ddos_guardian' no encontrado\n");
            std::exit(1);
        }

        int prog_fd = bpf_program__fd(prog);

        for (const auto &iface : ifaces_) {
            int ifindex = if_nametoindex(iface.c_str());
            if (!ifindex) {
                fprintf(stderr, "[!] if_nametoindex('%s'): %s\n",
                        iface.c_str(), strerror(errno));
                std::exit(1);
            }

            /* XDP_FLAGS_SKB_MODE (genérico) a propósito, NO el modo nativo
             * por default de bpf_program__attach_xdp() — bug encontrado
             * 2026-08-05: en modo nativo sobre estas NICs (Intel I225/I226,
             * driver igc), un socket AF_XDP insertado en xsks_map desde
             * userspace (bpf_map_update_elem, tanto vía
             * xsk_socket__update_xskmap() como escribiendo directo) queda
             * invisible para el propio programa XDP corriendo en modo
             * nativo — un bpf_map_lookup_elem() DIRECTO sobre esa misma
             * entrada, hecho desde DENTRO del programa, devuelve NULL pese
             * a que la escritura desde userspace no reportó error
             * (confirmado con contadores de diagnóstico: xsks_map_fd
             * insertado en slot 0/1, ifindex_slot resuelve al slot
             * correcto, pero el lookup en tiempo de ejecución del programa
             * siempre da NULL — 100% de las veces, cientos de miles de
             * paquetes). Con XDP_FLAGS_SKB_MODE — el mismo modo bajo el que
             * ya funcionaba históricamente cuando el programa estaba
             * adjunto a br0 (`ip -d link show br0` mostraba `xdpgeneric`,
             * nunca `xdp` a secas) y el mismo que usa
             * tests/test_af_xdp_redirect.py sobre veth (donde el relay sí
             * funciona, confirmado) — el mapa SÍ es visible correctamente.
             * No se investigó más a fondo la causa exacta en el kernel
             * (7.0.13) del lado nativo; esto evita el problema por
             * completo usando el modo que demostradamente funciona. */
            if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, nullptr) != 0) {
                fprintf(stderr, "[!] bpf_xdp_attach('%s', SKB_MODE): %s\n",
                        iface.c_str(), strerror(errno));
                std::exit(1);
            }
            xdp_attached_ifindexes_.push_back(ifindex);
            std::cout << "[*] XDP adjuntado a " << iface << " (modo SKB/genérico)\n";
        }
    }

    /* ── Fase 1: configura el triaje AF_XDP propio (opt-in) ──
     * Si HAWKEYE_INSPECTION_QUEUE no está seteada, no toca ifindex_slot
     * ni pinea xsks_map: la CAPA 4 de xdp_kern.c hace lookup, no encuentra
     * entrada, y el tráfico sigue XDP_PASS como si esta fase no existiera —
     * despliegues existentes sin AF_XDP configurado no cambian de
     * comportamiento. Debe correr ANTES de drop_privileges(): pinear en
     * bpffs requiere CAP_BPF/root.
     *
     * A cada interfaz en ifaces_ (en el mismo ORDEN en que se pasaron por
     * línea de comandos) se le asigna un slot 0,1,2... — src/af_xdp_consumer.cpp
     * DEBE recibir la misma lista, en el mismo orden, para que calcule los
     * mismos slots de forma independiente y registre cada socket AF_XDP en
     * el índice de xsks_map que corresponde (ver ifindex_slot en
     * kern/xdp_kern.c). No hay coordinación en caliente entre ambos
     * procesos más allá de esta convención posicional — a propósito, para
     * no necesitar un tercer canal (el pin de xsks_map ya cumple ese rol
     * para "está listo"). */
    void setup_triage() {
        const char *qenv = getenv("HAWKEYE_INSPECTION_QUEUE");
        if (!qenv) return;

        char *end = nullptr;
        long qid = strtol(qenv, &end, 10);
        if (end == qenv || *end != '\0' || qid < 0) {
            fprintf(stderr,
                "[!] HAWKEYE_INSPECTION_QUEUE='%s' inválida (esperaba un entero >= 0) — "
                "triaje Fase 1 desactivado.\n", qenv);
            return;
        }
        triage_queue_ = static_cast<int>(qid);

        if (ifaces_.size() > 2) {
            fprintf(stderr, "[!] Triaje Fase 1 solo soporta 1 o 2 interfaces (bridge de 2 "
                    "puertos), se pidieron %zu — desactivado.\n", ifaces_.size());
            triage_queue_ = -1;
            return;
        }

        int ifindex_slot_fd = get_fd_or(-1, "ifindex_slot");
        if (ifindex_slot_fd < 0) {
            fprintf(stderr,
                "[!] xdp_kern.o no tiene ifindex_slot (¿binario viejo?) — "
                "triaje Fase 1 desactivado.\n");
            triage_queue_ = -1;
            return;
        }

        for (size_t i = 0; i < ifaces_.size(); i++) {
            __u32 ifindex = if_nametoindex(ifaces_[i].c_str());
            if (!ifindex) {
                fprintf(stderr, "[!] if_nametoindex('%s') en setup_triage: %s — "
                        "triaje Fase 1 desactivado.\n", ifaces_[i].c_str(), strerror(errno));
                triage_queue_ = -1;
                return;
            }
            __u32 slot = static_cast<__u32>(i);
            if (bpf_map_update_elem(ifindex_slot_fd, &ifindex, &slot, BPF_ANY) != 0) {
                perror("[!] No se pudo escribir ifindex_slot, triaje desactivado");
                triage_queue_ = -1;
                return;
            }
            fprintf(stderr, "[dbg] ifindex_slot[ifindex=%u (%s)] = slot %u\n",
                    ifindex, ifaces_[i].c_str(), slot);
            std::cout << "[*] Fase 1: " << ifaces_[i] << " -> slot " << slot << "\n";
        }

        /* mkdir -p /sys/fs/bpf/hawkeye (bpffs debe estar montado en /sys/fs/bpf,
         * lo cual es responsabilidad del sistema, no de este programa). */
        if (mkdir(TRIAGE_PIN_DIR, 0700) != 0 && errno != EEXIST) {
            perror("[!] No se pudo crear directorio de pin, triaje desactivado");
            triage_queue_ = -1;
            return;
        }

        /* Re-pinear limpio: si quedó un pin de una corrida anterior (proceso
         * matado sin cleanup), bpf_map__pin() falla con EEXIST sobre un
         * fd que ya no es válido. Dos mapas dedicados (slot 0 -> _a, slot
         * 1 -> _b) — ver comentario largo en kern/xdp_kern.c. */
        unlink(XSKS_MAP_A_PIN_PATH);
        unlink(XSKS_MAP_B_PIN_PATH);

        auto *xsks_a_obj = bpf_object__find_map_by_name(obj_, "xsks_map_a");
        auto *xsks_b_obj = bpf_object__find_map_by_name(obj_, "xsks_map_b");
        if (!xsks_a_obj || !xsks_b_obj) {
            fprintf(stderr, "[!] xdp_kern.o no tiene xsks_map_a/xsks_map_b "
                    "(¿binario viejo?) — triaje Fase 1 desactivado.\n");
            triage_queue_ = -1;
            return;
        }
        if (bpf_map__pin(xsks_a_obj, XSKS_MAP_A_PIN_PATH) != 0) {
            perror("[!] No se pudo pinear xsks_map_a, triaje desactivado");
            triage_queue_ = -1;
            return;
        }
        if (bpf_map__pin(xsks_b_obj, XSKS_MAP_B_PIN_PATH) != 0) {
            perror("[!] No se pudo pinear xsks_map_b, triaje desactivado");
            triage_queue_ = -1;
            return;
        }

        std::cout << "[*] Fase 1: xsks_map_a/b pineados en " << TRIAGE_PIN_DIR
                  << " (esperando a src/af_xdp_consumer.cpp)\n";
    }

    /* Como get_fd (lambda local de load_bpf), pero sin abortar el proceso si
     * el mapa no existe — usado por setup_triage() para degradar con gracia
     * en vez de tumbar todo el predictor por un mapa opcional. */
    int get_fd_or(int fallback, const char *name) {
        auto *m = bpf_object__find_map_by_name(obj_, name);
        return m ? bpf_map__fd(m) : fallback;
    }

    /* ── Carga el modelo y verifica número de features ── */
    void load_model(const char *path) {
        safe_xgb(XGBoosterCreate(nullptr, 0, &booster_));
        safe_xgb(XGBoosterLoadModel(booster_, path));

        bst_ulong n_feat = 0;
        safe_xgb(XGBoosterGetNumFeature(booster_, &n_feat));
        if (n_feat != N_FEATURES) {
            fprintf(stderr,
                "[ERROR] Modelo espera %lu features, predictor.cpp usa %d.\n"
                "        Verifica que N_FEATURES coincida con train.py.\n",
                (unsigned long)n_feat, N_FEATURES);
            std::exit(1);
        }
        std::cout << "[*] Modelo cargado: " << path
                  << "  (" << n_feat << " features)\n";
    }

    /* ── Inferencia por lotes con XGBoost C API ≥ 2.0 ──
     * Un solo DMatrix de N filas × N_FEATURES columnas y una sola llamada a
     * XGBoosterPredictFromDMatrix, en vez de crear/destruir un DMatrix 1×9
     * por IP (costoso bajo ataques con miles de IPs concurrentes).
     * `flat_feats` debe tener exactamente n * N_FEATURES elementos
     * (fila i en flat_feats[i*N_FEATURES .. i*N_FEATURES+N_FEATURES)). */
    std::vector<double> predict_batch(std::vector<float> &flat_feats, size_t n) {
        std::vector<double> probs(n, 0.0);
        if (n == 0) return probs;

        DMatrixHandle dmat;
        safe_xgb(XGDMatrixCreateFromMat(flat_feats.data(),
                                         static_cast<bst_ulong>(n),
                                         N_FEATURES, NAN, &dmat));

        /* Config JSON — API estándar XGBoost ≥ 2.0             */
        /* type:0 = predicción de probabilidad (output_margin=0) */
        const char *cfg =
            R"({"training":false,"type":0,)"
            R"("iteration_begin":0,"iteration_end":0,"strict_shape":false})";

        bst_ulong     const *out_shape  = nullptr;
        bst_ulong            out_dim    = 0;
        float         const *out_result = nullptr;

        safe_xgb(XGBoosterPredictFromDMatrix(
            booster_, dmat, cfg, &out_shape, &out_dim, &out_result));

        /* Se espera un escalar de probabilidad por fila (mismo shape que ya
         * asumía el código de a-una-fila-por-vez). Si el modelo alguna vez
         * cambiara de forma (ej. multiclase), se detecta acá en vez de leer
         * memoria con un índice fuera de rango. */
        size_t total = 0;
        if (out_shape && out_dim > 0) {
            total = 1;
            for (bst_ulong i = 0; i < out_dim; ++i) total *= out_shape[i];
        }
        if (out_result && total == n) {
            for (size_t i = 0; i < n; ++i) probs[i] = out_result[i];
        } else if (out_result && total > 0) {
            fprintf(stderr,
                "[ERROR] predict_batch: shape de salida inesperado "
                "(total=%zu, filas esperadas=%zu). Se descarta este lote "
                "(ninguna IP se bloqueará en este ciclo).\n", total, n);
        }

        safe_xgb(XGDMatrixFree(dmat));
        return probs;
    }

    /* Limpia todos los elementos de un mapa BPF de manera segura */
    void wipe_map(int fd, const char* map_name) {
        ip_key_t key, next_key;
        const void *key_ptr = nullptr;
        std::vector<ip_key_t> keys_to_delete;
        
        while (bpf_map_get_next_key(fd, key_ptr, &next_key) == 0) {
            keys_to_delete.push_back(next_key);
            key = next_key;
            key_ptr = &key;
        }
        
        for (const ip_key_t &k : keys_to_delete) {
            bpf_map_delete_elem(fd, &k);
        }
        
        if (!keys_to_delete.empty()) {
            std::cout << "[*] Limpiados " << keys_to_delete.size() 
                      << " registros antiguos de " << map_name << "\n";
        }
    }

    const char        *iface_;
    std::vector<std::string> ifaces_;               /* interfaces físicas parseadas de iface_ */
    std::vector<int>         xdp_attached_ifindexes_; /* para desadjuntar en el destructor */
    struct bpf_object *obj_      = nullptr;
    int                stats_fd_     = -1;
    int                block_fd_     = -1;
    int                whitelist_fd_ = -1;
    int                triage_queue_ = -1; /* Fase 1, -1 = desactivado (ver setup_triage()) */
    BoosterHandle      booster_      = nullptr;
    bool               capture_enabled_        = false;
    int                capture_label_override_ = -1; /* -1 = sin forzar */
};

/* ════════════════════════════════════════════════════════════
 * PRIVILEGIOS
 * ════════════════════════════════════════════════════════════ */

/* Baja privilegios después de adjuntar XDP: root/CAP_NET_ADMIN solo hace falta
 * para el setup inicial (abrir el objeto BPF, adjuntar el programa). Las
 * operaciones posteriores sobre los mapas (lookup/update/delete) funcionan a
 * través de los file descriptors ya abiertos, sin necesitar más privilegios.
 * Si el binario se invocó con `sudo`, volvemos al usuario original
 * (SUDO_UID/SUDO_GID); si no hay esa info, seguimos como root y avisamos. */
static void drop_privileges() {
    if (geteuid() != 0)
        return;

    const char *sudo_uid = getenv("SUDO_UID");
    const char *sudo_gid = getenv("SUDO_GID");
    if (!sudo_uid || !sudo_gid) {
        fprintf(stderr,
            "[*] Corriendo como root sin SUDO_UID/SUDO_GID (¿no se invocó con sudo?) — "
            "no se pueden bajar privilegios automáticamente, se sigue como root.\n");
        return;
    }

    uid_t uid = (uid_t)strtoul(sudo_uid, nullptr, 10);
    gid_t gid = (gid_t)strtoul(sudo_gid, nullptr, 10);

    /* Orden importante: limpiar grupos suplementarios y bajar el gid mientras
     * todavía somos root, recién al final bajar el uid (irreversible). */
    if (setgroups(0, nullptr) != 0 ||
        setresgid(gid, gid, gid) != 0 ||
        setresuid(uid, uid, uid) != 0) {
        fprintf(stderr, "[!] No se pudieron bajar privilegios a uid=%u gid=%u: %s\n",
                (unsigned)uid, (unsigned)gid, strerror(errno));
        std::exit(1);
    }

    std::cout << "[*] Privilegios bajados a uid=" << uid << " gid=" << gid
              << " tras adjuntar XDP.\n";
}

/* ════════════════════════════════════════════════════════════
 * MAIN
 * ════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
            "Uso: %s <interfaz> <modelo.json>\n"
            "Ej:  sudo %s eth0 modelo.json\n",
            argv[0], argv[0]);
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    DDoSPredictor pred(argv[1], argv[2]);
    drop_privileges();
    pred.run();
    return 0;
}
