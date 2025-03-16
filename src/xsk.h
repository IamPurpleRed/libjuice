#ifndef PURPLERED_XSK_H
#define PURPLERED_XSK_H
#if USE_XDP

#include "udp.h"

#include <xdp/xsk.h>

typedef struct xsk_socket_info {
	void *umem_area;
	struct xsk_ring_prod fill; // 寫入空的 frame descriptor -> producer
	struct xsk_ring_cons comp;

	struct xsk_socket *xsk;
	int xsk_fd;
	struct xsk_ring_cons rx; // 讀取 frame descriptor 以獲得封包 -> consumer
	struct xsk_ring_prod tx;
} xsk_socket_info_t;

int initialize_xsk();
int add_port_to_ebpf_map(socket_t sock);
void remove_port_from_ebpf_map(socket_t sock);

#endif
#endif