#ifndef __TCP_PACKET_H__
#define __TCP_PACKET_H__

struct iq_packet_header {
    uint32_t num_samples;    // Number of I/Q samples in this packet
} __attribute__((packed));

// Structure for a single I/Q sample
struct iq_sample {
    uint16_t i;              // In-phase component
    uint16_t q;              // Quadrature component
} __attribute__((packed));

#endif /* __TCP_PACKET_H__ */
