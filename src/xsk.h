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

int initialize_xsk();
void *xsk_receive_loop(void *arg);
int receive_xsk_packets(void (*packet_handler)(void *packet, int packet_len));
void juice_packet_handler(void *packet, int packet_len);
int add_to_wss_map(socket_t sock);
void remove_from_wss_map(socket_t sock);
void free_xsk_resources(int option);

#endif
#endif