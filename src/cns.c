#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <ctype.h>

// mbedTLS headers for Crypto and Base64
#include <mbedtls/md.h>
#include <mbedtls/base64.h>

#define MAX_PACKET_SIZE 2048

// --- WIRE FORMAT HELPERS ---

void write_u16(uint8_t **p, uint16_t v) {
    (*p)[0] = (v >> 8) & 0xFF;
    (*p)[1] = v & 0xFF;
    *p += 2;
}

void write_u32(uint8_t **p, uint32_t v) {
    (*p)[0] = (v >> 24) & 0xFF;
    (*p)[1] = (v >> 16) & 0xFF;
    (*p)[2] = (v >> 8) & 0xFF;
    (*p)[3] = v & 0xFF;
    *p += 4;
}

void write_name(uint8_t **p, const char *name) {
    const char *start = name;
    while (*start) {
        const char *end = strchr(start, '.');
        if (!end) end = start + strlen(start);
        size_t len = end - start;
        if (len > 0) {
            *(*p)++ = (uint8_t)len;
            memcpy(*p, start, len);
            *p += len;
        }
        if (*end == '.') start = end + 1;
        else break;
    }
    *(*p)++ = 0;
}

void skip_name(const uint8_t *packet, size_t packet_len, size_t *offset) {
    while (*offset < packet_len) {
        uint8_t len = packet[*offset];
        if (len == 0) {
            *offset += 1;
            return;
        } else if ((len & 0xC0) == 0xC0) {
            *offset += 2;
            return;
        } else {
            *offset += len + 1;
        }
    }
}

// --- TSIG KEY PARSER ---

typedef struct {
    char name[256];
    char secret[256];
} TsigKey;

int parse_tsig_key_file(const char *file_path, TsigKey *key) {
    FILE *f = fopen(file_path, "r");
    if (!f) return -1;
    
    char line[512];
    strcpy(key->name, "default-key.");
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "key ", 4) == 0) {
            char *p1 = strchr(line, '"');
            if (p1) {
                char *p2 = strchr(p1 + 1, '"');
                if (p2) {
                    *p2 = '\0';
                    strcpy(key->name, p1 + 1);
                }
            }
        } else if (strstr(line, "secret")) {
            char *p1 = strchr(line, '"');
            if (p1) {
                char *p2 = strchr(p1 + 1, '"');
                if (p2) {
                    *p2 = '\0';
                    strcpy(key->secret, p1 + 1);
                }
            }
        } else if (strncmp(line, "Key:", 4) == 0) {
            char *p = line + 4;
            while (isspace((unsigned char)*p)) p++;
            char *end = p + strlen(p) - 1;
            while (end > p && isspace((unsigned char)*end)) *end-- = '\0';
            strcpy(key->secret, p);
        }
    }
    fclose(f);
    return key->secret[0] != '\0' ? 0 : -1;
}

// --- PACKET BUILDERS ---

size_t build_signed_txt_update(
    uint8_t *packet, const char *zone, const char *fqdn, const char *txt_value,
    const char *key_name, const uint8_t *raw_secret, size_t secret_len, 
    uint16_t tx_id, uint32_t ttl) 
{
    uint8_t *p = packet;
    
    write_u16(&p, tx_id);
    write_u16(&p, 0x2800); // Opcode 5 (Update)
    write_u16(&p, 1);      // ZOCOUNT
    write_u16(&p, 0);      // PRCOUNT
    write_u16(&p, 2);      // UPCOUNT
    write_u16(&p, 0);      // ARCOUNT (0 for digest calc)

    write_name(&p, zone);
    write_u16(&p, 6); // SOA
    write_u16(&p, 1); // IN

    // Delete old
    write_name(&p, fqdn);
    write_u16(&p, 16);  // TXT
    write_u16(&p, 255); // ANY
    write_u32(&p, 0);
    write_u16(&p, 0);

    // Add new
    write_name(&p, fqdn);
    write_u16(&p, 16); // TXT
    write_u16(&p, 1);  // IN
    write_u32(&p, ttl);
    size_t txt_len = strlen(txt_value);
    write_u16(&p, txt_len + 1);
    *p++ = (uint8_t)txt_len;
    memcpy(p, txt_value, txt_len);
    p += txt_len;

    // TSIG Digest Phase
    uint8_t tsig_payload[MAX_PACKET_SIZE];
    uint8_t *tp = tsig_payload;
    size_t msg_len = p - packet;
    memcpy(tp, packet, msg_len);
    tp += msg_len;

    uint64_t now = (uint64_t)time(NULL);
    
    write_name(&tp, key_name);
    write_u16(&tp, 255); // CLASS ANY
    write_u32(&tp, 0);   // TTL 0
    write_name(&tp, "hmac-sha256.");
    write_u16(&tp, (now >> 32) & 0xFFFF);
    write_u32(&tp, now & 0xFFFFFFFF);
    write_u16(&tp, 300); // Fudge
    write_u16(&tp, 0);   // Error
    write_u16(&tp, 0);   // Other len

    uint8_t mac[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, raw_secret, secret_len);
    mbedtls_md_hmac_update(&ctx, tsig_payload, tp - tsig_payload);
    mbedtls_md_hmac_finish(&ctx, mac);
    mbedtls_md_free(&ctx);

    // Patch ARCOUNT to 1
    packet[11] = 1;

    // Append TSIG RR to actual packet
    write_name(&p, key_name);
    write_u16(&p, 250); // TSIG
    write_u16(&p, 255); // ANY
    write_u32(&p, 0);
    write_u16(&p, 61);  // Length of hmac-sha256 rdata
    write_name(&p, "hmac-sha256.");
    write_u16(&p, (now >> 32) & 0xFFFF);
    write_u32(&p, now & 0xFFFFFFFF);
    write_u16(&p, 300); // Fudge
    write_u16(&p, 32);  // MAC Size
    memcpy(p, mac, 32); p += 32;
    write_u16(&p, tx_id);
    write_u16(&p, 0);
    write_u16(&p, 0);

    return p - packet;
}

size_t build_txt_query(uint8_t *packet, const char *fqdn, uint16_t tx_id) {
    uint8_t *p = packet;
    write_u16(&p, tx_id);
    write_u16(&p, 0x0100); // Query, RD flag
    write_u16(&p, 1);      // QDCOUNT
    write_u16(&p, 0);
    write_u16(&p, 0);
    write_u16(&p, 0);

    write_name(&p, fqdn);
    write_u16(&p, 16); // TXT
    write_u16(&p, 1);  // IN

    return p - packet;
}

// --- NETWORK ---

ssize_t send_udp_packet(const char *ip, const uint8_t *packet, size_t packet_len, uint16_t expected_id, uint8_t *resp) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(53);
    inet_pton(AF_INET, ip, &srv_addr.sin_addr);

    sendto(sock, packet, packet_len, 0, (struct sockaddr*)&srv_addr, sizeof(srv_addr));

    ssize_t bytes_read = recv(sock, resp, MAX_PACKET_SIZE, 0);
    close(sock);

    if (bytes_read < 12) return -1;

    uint16_t resp_id = (resp[0] << 8) | resp[1];
    if (resp_id != expected_id) return -1;

    return bytes_read;
}

// --- MAIN CLI ---

void print_usage() {
    fprintf(stderr, "Usage:\n"
                    "  zns lookup <fqdn> <server_ip>\n"
                    "  zns update [-t ttl] <zone> <fqdn> <txt_value> <key_name> <base64_secret> <server_ip>\n"
                    "  zns update [-t ttl] -k <key_file> <zone> <fqdn> <txt_value> <server_ip>\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { print_usage(); return 1; }

    srand((unsigned int)time(NULL));
    uint16_t tx_id = rand() & 0xFFFF;

    if (strcmp(argv[1], "lookup") == 0) {
        if (argc != 4) { print_usage(); return 1; }
        
        uint8_t packet[MAX_PACKET_SIZE];
        size_t len = build_txt_query(packet, argv[2], tx_id);
        
        uint8_t resp[MAX_PACKET_SIZE];
        ssize_t rlen = send_udp_packet(argv[3], packet, len, tx_id, resp);
        
        if (rlen < 0) {
            fprintf(stderr, "Lookup failed: Network error or timeout\n");
            return 1;
        }

        uint16_t flags = (resp[2] << 8) | resp[3];
        if ((flags & 0x000F) != 0) {
            fprintf(stderr, "Lookup failed! RCODE: %d\n", flags & 0x000F);
            return 1;
        }

        uint16_t qdcount = (resp[4] << 8) | resp[5];
        uint16_t ancount = (resp[6] << 8) | resp[7];
        
        size_t offset = 12;
        for (int i = 0; i < qdcount; i++) skip_name(resp, rlen, &offset), offset += 4;

        int found = 0;
        for (int i = 0; i < ancount; i++) {
            skip_name(resp, rlen, &offset);
            uint16_t rtype = (resp[offset] << 8) | resp[offset+1];
            uint16_t rdlength = (resp[offset+8] << 8) | resp[offset+9];
            offset += 10;
            
            if (rtype == 16) {
                found = 1;
                size_t txt_off = offset;
                size_t txt_end = offset + rdlength;
                printf("TXT: ");
                while (txt_off < txt_end) {
                    uint8_t slen = resp[txt_off++];
                    printf("\"%.*s\" ", slen, resp + txt_off);
                    txt_off += slen;
                }
                printf("\n");
            }
            offset += rdlength;
        }
        if (!found) printf("No TXT records found.\n");

    } else if (strcmp(argv[1], "update") == 0) {
        int arg_idx = 2;
        uint32_t ttl = 60; // Default TTL

        // Parse optional TTL arg
        if (arg_idx < argc && strcmp(argv[arg_idx], "-t") == 0) {
            if (arg_idx + 1 >= argc) { print_usage(); return 1; }
            ttl = (uint32_t)atoi(argv[arg_idx + 1]);
            arg_idx += 2;
        }

        const char *zone, *fqdn, *txt, *key_name, *b64_secret, *ip;
        TsigKey tsig_key = {0};

        if (arg_idx < argc && strcmp(argv[arg_idx], "-k") == 0) {
            if (argc - arg_idx != 6) { print_usage(); return 1; }
            if (parse_tsig_key_file(argv[arg_idx+1], &tsig_key) < 0) {
                fprintf(stderr, "Failed to parse key file\n");
                return 1;
            }
            zone = argv[arg_idx+2]; fqdn = argv[arg_idx+3]; txt = argv[arg_idx+4];
            ip = argv[arg_idx+5];
            key_name = tsig_key.name; b64_secret = tsig_key.secret;
        } else {
            if (argc - arg_idx != 6) { print_usage(); return 1; }
            zone = argv[arg_idx]; fqdn = argv[arg_idx+1]; txt = argv[arg_idx+2];
            key_name = argv[arg_idx+3]; b64_secret = argv[arg_idx+4];
            ip = argv[arg_idx+5];
        }

        uint8_t raw_secret[256];
        size_t secret_len = 0;
        if (mbedtls_base64_decode(raw_secret, sizeof(raw_secret), &secret_len, 
                                 (const unsigned char*)b64_secret, strlen(b64_secret)) != 0) {
            fprintf(stderr, "Invalid base64 secret\n");
            return 1;
        }

        uint8_t packet[MAX_PACKET_SIZE];
        size_t len = build_signed_txt_update(packet, zone, fqdn, txt, key_name, raw_secret, secret_len, tx_id, ttl);
        
        uint8_t resp[MAX_PACKET_SIZE];
        ssize_t rlen = send_udp_packet(ip, packet, len, tx_id, resp);
        
        if (rlen < 0) {
            fprintf(stderr, "Update failed: Network error\n");
            return 1;
        }

        uint16_t flags = (resp[2] << 8) | resp[3];
        if ((flags & 0x000F) == 0) {
            printf("Update successful! (RCODE: NOERROR)\n");
        } else {
            fprintf(stderr, "Update failed! RCODE: %d\n", flags & 0x000F);
            return 1;
        }
    } else {
        print_usage();
        return 1;
    }
    return 0;
}
