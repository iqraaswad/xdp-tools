// SPDX-License-Identifier: GPL-2.0

/******************************************************************************
 * Multiple include protection
 ******************************************************************************/
#ifndef _XDPDUMP_H_
#define _XDPDUMP_H_

/******************************************************************************
 * General definitions
 ******************************************************************************/
#define PERF_MAX_WAKEUP_EVENTS   64
#define PERF_MMAP_PAGE_COUNT	256
#define MAX_CPUS		24

/******************************************************************************
 * General used macros
 ******************************************************************************/
#ifndef __packed
#define __packed __attribute__((packed))
#endif

/*****************************************************************************
 * trace configuration structure
 *****************************************************************************/
struct trace_configuration {
	__u32 capture_if_ifindex;
	__u32 capture_snaplen;
	__u32 capture_prog_index;
};

/*****************************************************************************
 * perf data structures
 *****************************************************************************/
#define MDF_DIRECTION_FEXIT 1

struct pkt_trace_metadata {
	__u32 ifindex;
	__u32 rx_queue;
	__u16 pkt_len;
	__u16 cap_len;
	__u16 flags;
	__u16 prog_index;
	int   action;
} __packed;

#ifndef __bpf__
struct perf_sample_event {
	struct perf_event_header header;
	__u64 time;
	__u32 size;
	struct pkt_trace_metadata metadata;
	unsigned char packet[];
};

struct perf_lost_event {
	struct perf_event_header header;
	__u64 id;
	__u64 lost;
};

struct sniff_ip {
        u_char ip_vhl;          /* version << 4 | header length >> 2 */
        u_char ip_tos;          /* type of service */
        u_short ip_len;         /* total length */
        u_short ip_id;          /* identification */
        u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char ip_ttl;          /* time to live */
        u_char ip_p;            /* protocol */
        u_short ip_sum;         /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};

#endif

/******************************************************************************
 * End-of include file
 ******************************************************************************/
#endif /* _XDPDUMP_H_ */

