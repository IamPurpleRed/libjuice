#ifndef PURPLERED_XSK_H
#define PURPLERED_XSK_H
#if USE_XDP

#include "udp.h"

#include <xdp/xsk.h>

typedef struct xsk_socket_info {
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
} xsk_socket_info_t;

// INFO: 必須與 XDP 程式的 wss_metadata 資料結構保持一致
typedef struct wss_metadata {
	__u8 src_ip_version;
	union {
		__u32 src_ipv4;
		__u8 src_ipv6[16];
	};
	__u16 src_port;
	__u32 pipe_out_fd;
} wss_metadata_t;

// INFO: 必須與 XDP 程式的 wss_value 資料結構保持一致
typedef struct wss_value {
	__u32 socket_fd;
	__u32 pipe_out_fd;
} wss_value_t;

typedef struct pipe_recv {
	addr_record_t src;
	void *payload;
	int payload_len;
} pipe_recv_t;

int initialize_xsk(xsk_socket_info_t **juice_xsk);
void prime_fill_ring(struct xsk_ring_prod *fill);
int receive_xsk_packets(xsk_socket_info_t *juice_xsk);
void packet_handler(xsk_socket_info_t *juice_xsk, void *packet, int packet_len);
int create_wss_map_member(socket_t sock, int pipe_out, xsk_socket_info_t *juice_xsk);
void remove_from_wss_map(socket_t sock, xsk_socket_info_t *juice_xsk);
void free_xsk_resources(xsk_socket_info_t *juice_xsk, int option);

#endif
#endif