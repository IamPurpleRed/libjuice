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

	int cnt;  // test
} xsk_socket_info_t;

typedef struct wss_value {
	__u32 socket_fd;
	__u8 ip_version;
	union {
		__u32 src_ipv4;
		__u8 src_ipv6[16];
	};
	__u32 src_port;
} wss_value_t;

int initialize_xsk(xsk_socket_info_t **juice_xsk);
void prime_fill_ring(struct xsk_ring_prod *fill);
void *xsk_receive_loop(void *arg);
int receive_xsk_packets(xsk_socket_info_t *juice_xsk);
void packet_handler(xsk_socket_info_t *juice_xsk, void *packet, int packet_len);
int add_port_to_wss_map(socket_t sock, xsk_socket_info_t *juice_xsk);
void remove_from_wss_map(socket_t sock, xsk_socket_info_t *juice_xsk);
void update_src_addr(xsk_socket_info_t *juice_xsk, socket_t sock, addr_record_t *src);
void free_xsk_resources(xsk_socket_info_t *juice_xsk, int option);

#endif
#endif