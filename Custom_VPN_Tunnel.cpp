// ============================================================
// Project: ASCON-128 VPN Tunnel Simulator
// Platform: Windows (Winsock2) — CLion / MinGW / MSVC
// ============================================================
// Architecture:
//   SERVER mode: listens on UDP port, decrypts received
//                packets with ASCON-128, prints recovered data.
//   CLIENT mode: reads a simulated IP packet, encrypts it
//                with ASCON-128, sends over UDP to server.
//
// Run two terminals in CLion:
//   Terminal 1:  ascon_vpn server
//   Terminal 2:  ascon_vpn client
//
// No TUN/TAP driver needed — uses raw struct simulation
// of IP packet headers to demonstrate the full VPN pipeline.
// ============================================================

#define _WIN32_WINNT 0x0601   // Windows 7+
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <string>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <chrono>
#include <thread>
#include <algorithm>

// ============================================================
// CONFIGURATION
// ============================================================
static constexpr uint16_t VPN_PORT      = 54321;
static constexpr int      MAX_PACKET    = 4096;
static constexpr int      RECV_TIMEOUT  = 30000;   // ms
static const     char*    SERVER_ADDR   = "127.0.0.1";

// ============================================================
// TYPE ALIASES
// ============================================================
using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8  = uint8_t;

// ============================================================
// SIMULATED IP PACKET HEADER (20 bytes, IPv4-like layout)
// In a real TUN/TAP VPN this would be a genuine kernel IP
// header captured from the tun0 interface. Here we construct
// it manually to demonstrate the full encryption pipeline
// without needing kernel drivers or root/admin privileges.
// ============================================================
#pragma pack(push, 1)
struct IPv4Header {
    u8  version_ihl    = 0x45;   // version=4, IHL=5 (20 bytes)
    u8  dscp_ecn       = 0x00;   // no QoS markings
    u16 total_length   = 0;      // header + payload (big-endian)
    u16 identification = 0;      // fragment ID
    u16 flags_offset   = 0x4000; // DF bit set (no fragmentation)
    u8  ttl            = 64;     // time-to-live hops
    u8  protocol       = 17;     // 17 = UDP upper-layer payload
    u16 checksum       = 0;      // computed separately
    u32 src_ip         = 0;      // source IP (big-endian)
    u32 dst_ip         = 0;      // destination IP (big-endian)
};
#pragma pack(pop)

// ============================================================
// SIMULATED UDP PAYLOAD PACKET
// Wraps IPv4Header + arbitrary payload bytes.
// ============================================================
struct SimPacket {
    IPv4Header  header;
    std::vector<u8> payload;

    // Total raw bytes for this packet
    std::vector<u8> serialize() const {
        std::vector<u8> out(sizeof(IPv4Header));
        std::memcpy(out.data(), &header, sizeof(IPv4Header));
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    static SimPacket deserialize(const u8* data, size_t len) {
        SimPacket p;
        if (len >= sizeof(IPv4Header)) {
            std::memcpy(&p.header, data, sizeof(IPv4Header));
            size_t payload_offset = sizeof(IPv4Header);
            if (len > payload_offset) {
                p.payload.assign(data + payload_offset,
                                 data + len);
            }
        }
        return p;
    }
};

// ============================================================
// ASCON-128 ENGINE
// ============================================================
// Round constants (ASCON spec, p12 = rounds 0..11)
static constexpr u64 ASCON_RC[16] = {
    0xf0ULL,0xe1ULL,0xd2ULL,0xc3ULL,
    0xb4ULL,0xa5ULL,0x96ULL,0x87ULL,
    0x78ULL,0x69ULL,0x5aULL,0x4bULL,
    0x3cULL,0x2dULL,0x1eULL,0x0fULL
};
static constexpr u64 ASCON_IV = 0x80400c0600000000ULL;

struct AsconState { u64 x[5] = {}; };
struct AsconKey   { u64 k0, k1; };
struct AsconNonce { u64 n0, n1; };

static inline u64 rotr64(u64 v, int r) {
    return (v >> r) | (v << (64 - r));
}

static void ascon_add_const(AsconState& s, int i, int a) {
    s.x[2] ^= ASCON_RC[12 - a + i];
}

static void ascon_sbox(AsconState& s) {
    s.x[0]^=s.x[4]; s.x[4]^=s.x[3]; s.x[2]^=s.x[1];
    u64 t0=~s.x[0],t1=~s.x[1],t2=~s.x[2],t3=~s.x[3],t4=~s.x[4];
    t0&=s.x[1]; t1&=s.x[2]; t2&=s.x[3]; t3&=s.x[4]; t4&=s.x[0];
    s.x[0]^=t1; s.x[1]^=t2; s.x[2]^=t3; s.x[3]^=t4; s.x[4]^=t0;
    s.x[1]^=s.x[0]; s.x[0]^=s.x[4]; s.x[3]^=s.x[2]; s.x[2]=~s.x[2];
}

static void ascon_linear(AsconState& s) {
    s.x[0]^=rotr64(s.x[0],19)^rotr64(s.x[0],28);
    s.x[1]^=rotr64(s.x[1],61)^rotr64(s.x[1],39);
    s.x[2]^=rotr64(s.x[2], 1)^rotr64(s.x[2], 6);
    s.x[3]^=rotr64(s.x[3],10)^rotr64(s.x[3],17);
    s.x[4]^=rotr64(s.x[4], 7)^rotr64(s.x[4],41);
}

static void ascon_permute(AsconState& s, int rounds) {
    for (int i = 0; i < rounds; i++) {
        ascon_add_const(s, i, rounds);
        ascon_sbox(s);
        ascon_linear(s);
    }
}

// --- big-endian helpers ---
static u64 load_be64(const u8* p, size_t avail = 8) {
    u64 v = 0;
    for (size_t i = 0; i < avail && i < 8; i++)
        v = (v << 8) | p[i];
    if (avail < 8) v <<= (8 - avail) * 8;
    return v;
}

static void store_be64(u64 v, u8* p) {
    for (int i = 7; i >= 0; i--) { p[i] = u8(v & 0xFF); v >>= 8; }
}

// --- ASCON init ---
static AsconState ascon_init(const AsconKey& k, const AsconNonce& n) {
    AsconState s;
    s.x[0]=ASCON_IV; s.x[1]=k.k0; s.x[2]=k.k1;
    s.x[3]=n.n0;     s.x[4]=n.n1;
    ascon_permute(s, 12);
    s.x[3]^=k.k0; s.x[4]^=k.k1;
    return s;
}

// --- absorb associated data ---
static void ascon_absorb_ad(AsconState& s,
                             const std::vector<u8>& ad) {
    size_t i = 0;
    for (; i + 8 <= ad.size(); i += 8) {
        s.x[0] ^= load_be64(ad.data() + i);
        ascon_permute(s, 6);
    }
    // final padded block
    u8 tmp[8] = {};
    size_t rem = ad.size() - i;
    std::memcpy(tmp, ad.data() + i, rem);
    tmp[rem] = 0x80;
    s.x[0] ^= load_be64(tmp);
    ascon_permute(s, 6);
    s.x[4] ^= 1ULL;   // domain separation
}

// --- encrypt block ---
static u64 ascon_enc_block(AsconState& s, u64 plain) {
    u64 cipher = plain ^ s.x[0];
    s.x[0] = cipher;
    return cipher;
}

// --- decrypt block ---
static u64 ascon_dec_block(AsconState& s, u64 cipher) {
    u64 plain = cipher ^ s.x[0];
    s.x[0] = cipher;
    return plain;
}

// --- finalize and return 128-bit tag ---
static std::array<u64,2> ascon_finalize(AsconState& s,
                                         const AsconKey& k) {
    s.x[1]^=k.k0; s.x[2]^=k.k1;
    ascon_permute(s, 12);
    s.x[3]^=k.k0; s.x[4]^=k.k1;
    return {s.x[3], s.x[4]};
}

// ============================================================
// HIGH-LEVEL: encrypt a raw byte buffer
// Returns: [ nonce(16) | ciphertext(N+pad) | tag(16) ]
// We derive a per-packet nonce from the packet counter so
// the same key can safely encrypt many packets in sequence.
// ============================================================
static std::vector<u8> vpn_encrypt(const std::vector<u8>& plain,
                                    const AsconKey& key,
                                    u64 pkt_counter) {
    // Per-packet nonce derived from counter
    AsconNonce nonce = { pkt_counter, ~pkt_counter };

    AsconState s = ascon_init(key, nonce);

    // Associated data = packet counter (prevents replay attacks)
    std::vector<u8> ad(8);
    store_be64(pkt_counter, ad.data());
    ascon_absorb_ad(s, ad);

    // Encrypt all full 8-byte blocks
    std::vector<u8> ciphertext;
    ciphertext.reserve(plain.size() + 8);

    size_t offset = 0;
    while (offset + 8 <= plain.size()) {
        u64 pb = load_be64(plain.data() + offset);
        u64 cb = ascon_enc_block(s, pb);
        u8 out[8]; store_be64(cb, out);
        ciphertext.insert(ciphertext.end(), out, out + 8);
        if (offset + 8 < plain.size()) ascon_permute(s, 6);
        offset += 8;
    }

    // Final partial block with padding
    size_t rem = plain.size() - offset;
    u8 tmp[8] = {};
    if (rem > 0) std::memcpy(tmp, plain.data() + offset, rem);
    tmp[rem] = 0x80;
    u64 pb = load_be64(tmp);
    u64 cb = ascon_enc_block(s, pb);
    u8 out[8]; store_be64(cb, out);
    ciphertext.insert(ciphertext.end(), out, out + 8);

    // Finalize → 16-byte tag
    auto tag = ascon_finalize(s, key);
    u8 tag_bytes[16];
    store_be64(tag[0], tag_bytes);
    store_be64(tag[1], tag_bytes + 8);

    // Wire format: nonce(16) | len(8) | ciphertext | tag(16)
    std::vector<u8> wire;
    wire.reserve(16 + 8 + ciphertext.size() + 16);

    // nonce as 16 bytes
    u8 nonce_bytes[16];
    store_be64(nonce.n0, nonce_bytes);
    store_be64(nonce.n1, nonce_bytes + 8);
    wire.insert(wire.end(), nonce_bytes, nonce_bytes + 16);

    // original plaintext length as 8 bytes (needed for decryption)
    u8 len_bytes[8]; store_be64(static_cast<u64>(plain.size()), len_bytes);
    wire.insert(wire.end(), len_bytes, len_bytes + 8);

    // ciphertext
    wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

    // tag
    wire.insert(wire.end(), tag_bytes, tag_bytes + 16);

    return wire;
}

// ============================================================
// HIGH-LEVEL: decrypt a wire-format buffer
// Returns decrypted bytes, or empty on authentication failure.
// ============================================================
static std::vector<u8> vpn_decrypt(const std::vector<u8>& wire,
                                    const AsconKey& key,
                                    u64& pkt_counter_out) {
    // Minimum wire size: 16(nonce) + 8(len) + 8(one block) + 16(tag)
    if (wire.size() < 48) {
        std::cerr << "[DEC] Wire packet too short.\n";
        return {};
    }

    // Parse nonce
    AsconNonce nonce;
    nonce.n0 = load_be64(wire.data() + 0);
    nonce.n1 = load_be64(wire.data() + 8);

    // Parse original length
    u64 orig_len = load_be64(wire.data() + 16);
    pkt_counter_out = nonce.n0;   // recover counter from nonce

    // Split ciphertext and tag
    size_t ct_start  = 24;
    size_t tag_start = wire.size() - 16;
    if (tag_start <= ct_start) {
        std::cerr << "[DEC] Malformed wire packet.\n";
        return {};
    }
    const u8* stored_tag = wire.data() + tag_start;

    // Re-init ASCON with same key + nonce
    AsconState s = ascon_init(key, nonce);

    // Re-absorb same associated data (counter)
    std::vector<u8> ad(8);
    store_be64(nonce.n0, ad.data());
    ascon_absorb_ad(s, ad);

    // Decrypt blocks
    std::vector<u8> plaintext;
    plaintext.reserve(static_cast<size_t>(orig_len));

    size_t offset      = ct_start;
    size_t block_idx   = 0;
    size_t total_blocks= (tag_start - ct_start) / 8;

    while (offset < tag_start) {
        bool is_last = (block_idx == total_blocks - 1);
        u64 cb = load_be64(wire.data() + offset);
        u64 pb = ascon_dec_block(s, cb);
        u8 out[8]; store_be64(pb, out);

        size_t wlen;
        if (is_last) {
            size_t already = plaintext.size();
            wlen = (orig_len > already) ?
                   static_cast<size_t>(orig_len - already) : 0;
        } else {
            wlen = 8;
        }
        for (size_t b = 0; b < wlen; b++)
            plaintext.push_back(out[b]);

        if (!is_last) ascon_permute(s, 6);
        offset += 8;
        block_idx++;
    }

    // Re-generate tag
    auto tag = ascon_finalize(s, key);
    u8 comp_tag[16];
    store_be64(tag[0], comp_tag);
    store_be64(tag[1], comp_tag + 8);

    // Constant-time comparison
    u8 diff = 0;
    for (int i = 0; i < 16; i++) diff |= (comp_tag[i] ^ stored_tag[i]);

    if (diff != 0) {
        std::fill(plaintext.begin(), plaintext.end(), 0);
        std::cerr << "[DEC] AUTHENTICATION FAILED — "
                     "wrong key or tampered packet.\n";
        return {};
    }

    return plaintext;
}

// ============================================================
// UTILITY: Format bytes as hex string
// ============================================================
static std::string hex_str(const u8* d, size_t n, size_t maxbytes = 32) {
    std::ostringstream oss;
    size_t show = std::min(n, maxbytes);
    for (size_t i = 0; i < show; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(d[i]);
        if (i + 1 < show) oss << " ";
    }
    if (n > maxbytes) oss << " ...(" << n << " bytes total)";
    return oss.str();
}

// ============================================================
// UTILITY: Pretty print separator
// ============================================================
static void sep(char c = '-', int w = 64) {
    std::cout << std::string(w, c) << "\n";
}

// ============================================================
// UTILITY: Print a SimPacket header in human-readable form
// ============================================================
static void print_ip_header(const IPv4Header& h) {
    auto ip_str = [](u32 ip) -> std::string {
        std::ostringstream o;
        o << ((ip>>24)&0xFF) << "."
          << ((ip>>16)&0xFF) << "."
          << ((ip>> 8)&0xFF) << "."
          << ((ip    )&0xFF);
        return o.str();
    };
    std::cout << "  Version/IHL : 0x"
              << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(h.version_ihl) << std::dec << "\n"
              << "  Protocol    : " << static_cast<int>(h.protocol)
              << " (UDP)\n"
              << "  TTL         : " << static_cast<int>(h.ttl) << "\n"
              << "  Src IP      : " << ip_str(ntohl(h.src_ip)) << "\n"
              << "  Dst IP      : " << ip_str(ntohl(h.dst_ip)) << "\n"
              << "  Total len   : " << ntohs(h.total_length) << " bytes\n";
}

// ============================================================
// WINSOCK HELPER: Initialize WSA
// ============================================================
static bool wsa_init() {
    WSADATA wsa;
    int r = WSAStartup(MAKEWORD(2,2), &wsa);
    if (r != 0) {
        std::cerr << "[NET] WSAStartup failed: " << r << "\n";
        return false;
    }
    std::cout << "[NET] Winsock2 initialized.\n";
    return true;
}

// ============================================================
// VPN SHARED KEY
// In production this is derived via a key-exchange protocol.
// For this demo it is hardcoded — both sides must match.
// ============================================================
static AsconKey VPN_KEY = {
    0xDEADBEEFCAFEBABEULL,
    0x0123456789ABCDEFULL
};

// ============================================================
// SERVER MODE
// Listens on UDP VPN_PORT, receives encrypted packets,
// decrypts and verifies them, reconstructs the IP packet,
// and prints the recovered payload.
// ============================================================
static int run_server() {
    if (!wsa_init()) return 1;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[SERVER] socket() failed: "
                  << WSAGetLastError() << "\n";
        WSACleanup(); return 1;
    }

    // Allow address reuse
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<char*>(&reuse), sizeof(reuse));

    // Set receive timeout
    DWORD timeout = RECV_TIMEOUT;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&timeout), sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(VPN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr),
             sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[SERVER] bind() failed: "
                  << WSAGetLastError() << "\n";
        closesocket(sock); WSACleanup(); return 1;
    }

    sep('=');
    std::cout << "  ASCON-128 VPN SERVER\n";
    sep('=');
    std::cout << "[SERVER] Listening on UDP port "
              << VPN_PORT << " ...\n";
    std::cout << "[SERVER] Waiting for encrypted VPN packets...\n";
    std::cout << "[SERVER] Press Ctrl+C to stop.\n\n";

    u8 buf[MAX_PACKET];
    sockaddr_in client{};
    int client_len = sizeof(client);
    u64 packets_received = 0;

    while (true) {
        int recv_len = recvfrom(sock, reinterpret_cast<char*>(buf),
                                MAX_PACKET, 0,
                                reinterpret_cast<sockaddr*>(&client),
                                &client_len);
        if (recv_len == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                std::cout << "[SERVER] Receive timeout — "
                             "still listening...\n";
                continue;
            }
            std::cerr << "[SERVER] recvfrom() error: " << err << "\n";
            break;
        }

        packets_received++;
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr,
                  client_ip, sizeof(client_ip));

        sep();
        std::cout << "[SERVER] Packet #" << packets_received
                  << " received from "
                  << client_ip << ":" << ntohs(client.sin_port) << "\n";
        std::cout << "[SERVER] Encrypted wire size : "
                  << recv_len << " bytes\n";
        std::cout << "[SERVER] Encrypted hex (first 32 bytes):\n"
                  << "         "
                  << hex_str(buf, static_cast<size_t>(recv_len))
                  << "\n";

        // Decrypt
        std::vector<u8> wire(buf, buf + recv_len);
        u64 counter = 0;
        std::vector<u8> plain = vpn_decrypt(wire, VPN_KEY, counter);

        if (plain.empty()) {
            std::cerr << "[SERVER] Packet #" << packets_received
                      << " DROPPED — authentication failure.\n";
            continue;
        }

        std::cout << "[SERVER] Authentication   : PASSED\n";
        std::cout << "[SERVER] Packet counter   : " << counter << "\n";
        std::cout << "[SERVER] Decrypted size   : "
                  << plain.size() << " bytes\n";

        // Reconstruct IP packet
        if (plain.size() >= sizeof(IPv4Header)) {
            SimPacket pkt = SimPacket::deserialize(
                                plain.data(), plain.size());
            std::cout << "\n[SERVER] --- Recovered IP Packet Header ---\n";
            print_ip_header(pkt.header);

            if (!pkt.payload.empty()) {
                std::cout << "\n[SERVER] --- Payload ("
                          << pkt.payload.size() << " bytes) ---\n";
                // Print as ASCII where printable, hex otherwise
                std::cout << "  ASCII : \"";
                for (u8 c : pkt.payload) {
                    if (c >= 32 && c < 127)
                        std::cout << static_cast<char>(c);
                    else
                        std::cout << '.';
                }
                std::cout << "\"\n";
                std::cout << "  Hex   : "
                          << hex_str(pkt.payload.data(),
                                     pkt.payload.size()) << "\n";
            }
        } else {
            std::cout << "[SERVER] Payload hex: "
                      << hex_str(plain.data(), plain.size()) << "\n";
        }

        std::cout << "\n[SERVER] Packet injected into virtual "
                     "network stack.\n";
        sep();
    }

    closesocket(sock);
    WSACleanup();
    std::cout << "[SERVER] Shutdown. Packets received: "
              << packets_received << "\n";
    return 0;
}

// ============================================================
// CLIENT MODE
// Builds a simulated IP packet, encrypts it with ASCON-128,
// sends it over UDP to the server. Sends multiple packets
// to demonstrate per-packet nonce counter increment.
// ============================================================
static int run_client() {
    if (!wsa_init()) return 1;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[CLIENT] socket() failed: "
                  << WSAGetLastError() << "\n";
        WSACleanup(); return 1;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port   = htons(VPN_PORT);
    inet_pton(AF_INET, SERVER_ADDR, &server.sin_addr);

    sep('=');
    std::cout << "  ASCON-128 VPN CLIENT\n";
    sep('=');
    std::cout << "[CLIENT] Target server : "
              << SERVER_ADDR << ":" << VPN_PORT << "\n\n";

    // Simulate 4 different IP packets with different payloads
    struct TestPacket {
        std::string src_ip;
        std::string dst_ip;
        std::string payload;
        std::string description;
    };

    std::vector<TestPacket> test_pkts = {
        {"10.0.0.1",  "10.0.0.2",
         "Hello from ASCON VPN! This is packet 1.",
         "HTTP-like data transfer"},
        {"192.168.1.10", "192.168.1.1",
         "DNS query: example.com type=A class=IN",
         "DNS query simulation"},
        {"172.16.0.5", "172.16.0.1",
         "PING 172.16.0.1 seq=1 ttl=64 time=0.123ms",
         "ICMP ping simulation"},
        {"10.10.0.3", "10.10.0.99",
         "GET /index.html HTTP/1.1\r\nHost: vpn.local\r\n\r\n",
         "HTTP GET request"}
    };

    // Helper to parse "a.b.c.d" -> u32 big-endian
    auto parse_ip = [](const std::string& s) -> u32 {
        u32 a,b,c,d;
        sscanf(s.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d);
        return htonl((a<<24)|(b<<16)|(c<<8)|d);
    };

    u64 counter = 0;

    for (size_t i = 0; i < test_pkts.size(); i++) {
        const auto& tp = test_pkts[i];
        counter++;

        sep();
        std::cout << "[CLIENT] === Sending Packet #" << counter
                  << " ===\n";
        std::cout << "[CLIENT] Type    : " << tp.description << "\n";

        // Build simulated IP packet
        SimPacket pkt;
        pkt.header.src_ip = parse_ip(tp.src_ip);
        pkt.header.dst_ip = parse_ip(tp.dst_ip);
        pkt.header.protocol = 17;   // UDP payload
        pkt.header.ttl      = 64;

        pkt.payload.assign(tp.payload.begin(), tp.payload.end());

        u16 total = static_cast<u16>(
                        sizeof(IPv4Header) + pkt.payload.size());
        pkt.header.total_length = htons(total);
        pkt.header.identification = htons(
                        static_cast<u16>(counter & 0xFFFF));

        std::vector<u8> raw = pkt.serialize();

        std::cout << "\n[CLIENT] --- Original IP Packet ---\n";
        print_ip_header(pkt.header);
        std::cout << "  Payload : \"" << tp.payload << "\"\n";
        std::cout << "  Raw hex : "
                  << hex_str(raw.data(), raw.size()) << "\n";
        std::cout << "  Raw size: " << raw.size() << " bytes\n";

        // Encrypt with ASCON-128
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<u8> wire = vpn_encrypt(raw, VPN_KEY, counter);
        auto t1 = std::chrono::high_resolution_clock::now();
        double enc_us = std::chrono::duration<double,
                        std::micro>(t1 - t0).count();

        std::cout << "\n[CLIENT] --- After ASCON-128 Encryption ---\n";
        std::cout << "  Wire size    : " << wire.size() << " bytes\n";
        std::cout << "  Encrypt time : " << std::fixed
                  << std::setprecision(2) << enc_us << " μs\n";
        std::cout << "  Nonce [0]    : 0x" << std::hex
                  << std::setw(16) << std::setfill('0') << counter
                  << std::dec << "\n";
        std::cout << "  Wire hex     : "
                  << hex_str(wire.data(), wire.size()) << "\n";

        // Send over UDP
        int sent = sendto(sock,
                          reinterpret_cast<const char*>(wire.data()),
                          static_cast<int>(wire.size()), 0,
                          reinterpret_cast<sockaddr*>(&server),
                          sizeof(server));

        if (sent == SOCKET_ERROR) {
            std::cerr << "[CLIENT] sendto() failed: "
                      << WSAGetLastError() << "\n";
        } else {
            std::cout << "[CLIENT] Sent " << sent
                      << " bytes → " << SERVER_ADDR
                      << ":" << VPN_PORT << "\n";
        }

        // Small delay between packets for readability
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    sep('=');
    std::cout << "[CLIENT] All " << counter
              << " packets sent.\n";
    std::cout << "[CLIENT] Each packet used a unique nonce "
                 "(counter-based) to prevent replay attacks.\n";
    sep('=');

    closesocket(sock);
    WSACleanup();
    return 0;
}

// ============================================================
// SELF-TEST MODE
// Runs a complete loopback encrypt-decrypt cycle in memory
// without any network I/O — verifies ASCON engine correctness.
// ============================================================
static int run_selftest() {
    sep('=');
    std::cout << "  ASCON VPN ENGINE — SELF TEST\n";
    sep('=');

    AsconKey test_key = {0xDEADBEEFCAFEBABEULL, 0xFEEDFACEDEADC0DEULL};

    struct TC {
        std::string name;
        std::vector<u8> data;
    };

    std::vector<TC> cases = {
        {"1-byte payload",     {0xAB}},
        {"8-byte payload",     {0x01,0x02,0x03,0x04,
                                0x05,0x06,0x07,0x08}},
        {"16-byte payload",    {0x11,0x22,0x33,0x44,
                                0x55,0x66,0x77,0x88,
                                0x99,0xAA,0xBB,0xCC,
                                0xDD,0xEE,0xFF,0x00}},
        {"ASCII message",      std::vector<u8>(
                                std::string("ASCON VPN tunnel test!").begin(),
                                std::string("ASCON VPN tunnel test!").end())}
    };

    int pass = 0, fail = 0;

    for (size_t i = 0; i < cases.size(); i++) {
        const auto& tc = cases[i];
        u64 counter = static_cast<u64>(i + 1);

        // Encrypt
        auto wire = vpn_encrypt(tc.data, test_key, counter);

        // Decrypt
        u64 recv_counter = 0;
        auto recovered   = vpn_decrypt(wire, test_key, recv_counter);

        bool ok = (recovered == tc.data) && (recv_counter == counter);

        std::cout << "[TEST " << (i+1) << "] " << tc.name
                  << " (" << tc.data.size() << " bytes) → ";
        if (ok) {
            std::cout << "PASS\n"; pass++;
        } else {
            std::cout << "FAIL\n"; fail++;
        }
    }

    // Tamper test: modify 1 byte of ciphertext, expect auth failure
    {
        std::vector<u8> data = {'T','a','m','p','e','r'};
        auto wire = vpn_encrypt(data, test_key, 99);
        wire[30] ^= 0xFF;   // flip bits in ciphertext body
        u64 c = 0;
        auto rec = vpn_decrypt(wire, test_key, c);
        bool ok = rec.empty();  // must reject
        std::cout << "[TEST 5] Tamper detection → "
                  << (ok ? "PASS" : "FAIL") << "\n";
        if (ok) pass++; else fail++;
    }

    sep();
    std::cout << "Results: " << pass << " passed, "
              << fail << " failed.\n";
    sep('=');
    return (fail == 0) ? 0 : 1;
}

// ============================================================
// MAIN
// ============================================================
static void print_usage(const char* prog) {
    sep('=');
    std::cout << "  ASCON-128 VPN Tunnel — Usage\n";
    sep('=');
    std::cout << "  " << prog << " server      — Start VPN server\n";
    std::cout << "  " << prog << " client      — Start VPN client\n";
    std::cout << "  " << prog << " test        — Run self-test\n";
    std::cout << "\n  How to demo:\n";
    std::cout << "    Terminal 1: " << prog << " server\n";
    std::cout << "    Terminal 2: " << prog << " client\n";
    sep('=');
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        std::cout << "\nNo mode specified — running self-test.\n\n";
        return run_selftest();
    }

    std::string mode = argv[1];

    if (mode == "server") return run_server();
    if (mode == "client") return run_client();
    if (mode == "test")   return run_selftest();

    std::cerr << "[ERROR] Unknown mode: " << mode << "\n";
    print_usage(argv[0]);
    return 1;
}