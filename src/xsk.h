#ifndef PURPLERED_XSK_H
#define PURPLERED_XSK_H
#if USE_XDP

#include "udp.h"

#include <stdatomic.h>
#include <xdp/xsk.h>

// INFO: 紀錄 XDP 所需的所有內容（全域只有一個，為 conn_registry_t 的成員）
typedef struct xdp_info {
	uint32_t wss_map_fd;
	uint32_t xsk_map_fd;

	void *umem_area;

	struct xsk_umem *umem;
	struct xsk_ring_prod fill; // 寫入空的 frame descriptor -> producer
	struct xsk_ring_cons comp;

	struct xsk_socket *xsk;
	struct xsk_ring_cons rx; // 讀取 frame descriptor 以獲得封包 -> consumer
	struct xsk_ring_prod tx;
	int xsk_fd;
} xdp_info_t;

// INFO: 必須與 XDP 程式的 struct wss_metadata 保持一致
typedef struct wss_metadata {
	__u8 src_ip_version;
	union {
		__u32 src_ipv4;
		__u8 src_ipv6[16];
	};
	__u16 src_port;
	__u64 xdp_agent_rb_ptr;
} wss_metadata_t;

// INFO: xdp_agent_rb_t 的傳送單位
typedef struct agent_recv {
	int payload_len;
	void *payload;
	addr_record_t *src;
} agent_recv_t;

// INFO: XSK 將封包分配給各個 agent 所使用的 ring buffer
typedef struct xdp_agent_rb {
	int efd;
	agent_recv_t buffer[1024];
	atomic_uint head; // consumer read (agent)
	atomic_uint tail; // producer write (XSK)
} xdp_agent_rb_t;

int initialize_juice_xdp(xdp_info_t **juice_xdp_ptr);
void juice_xdp_cleanup(xdp_info_t *juice_xdp, int option);
int initialize_recv_rb(xdp_agent_rb_t **recv_rb_ptr);
void recv_rb_cleanup(xdp_agent_rb_t *recv_rb);
int add_port_to_wss_map(xdp_info_t *juice_xdp, socket_t sock, xdp_agent_rb_t *ptr);
void remove_port_from_wss_map(socket_t sock, xdp_info_t *juice_xdp);
int receive_xsk_packets(xdp_info_t *juice_xdp);

#endif
#endif