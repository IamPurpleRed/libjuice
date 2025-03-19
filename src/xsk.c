#if USE_XDP

#include "xsk.h"
#include "log.h"

#include <bpf/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <socket.h>
#include <stdlib.h>
#include <sys/mman.h>

static xsk_socket_info_t *juice_xsk = NULL;

int initialize_xsk() {
	if (juice_xsk)
		return 0; // 已初始化

	juice_xsk = calloc(1, sizeof(xsk_socket_info_t));
	if (!juice_xsk) {
		JLOG_FATAL("PurpleRed: Memory allocation for juice_xsk failed");
		return -1;
	}

	// INFO: 尋找 wss_map 的 file descriptor
	uint32_t wss_map_fd = bpf_obj_get("/sys/fs/bpf/wss_map");
	if (wss_map_fd < 0) {
		JLOG_FATAL("PurpleRed: Failed to get wss_map");
		return -1;
	}
	juice_xsk->wss_map_fd = wss_map_fd;

	// INFO: 尋找 xsk_map 的 file descriptor
	uint32_t xsk_map_fd = bpf_obj_get("/sys/fs/bpf/xsk_map");
	if (xsk_map_fd < 0) {
		JLOG_FATAL("PurpleRed: Failed to get xsk_map");
		return -1;
	}
	juice_xsk->xsk_map_fd = xsk_map_fd;

	int ifindex = if_nametoindex(XDP_IFNAME);
	if (ifindex == 0) {
		JLOG_FATAL("PurpleRed: XDP_IFNAME not found");
		free_xsk_resources(0);
		return -1;
	}

	// INFO: 在 user space 分配 4096 * 4096 Byte 的空間
	void *umem_area = mmap(NULL, 4096 * 4096, PROT_READ | PROT_WRITE,
	                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (umem_area == MAP_FAILED) {
		JLOG_FATAL("PurpleRed: Memory allocation for umem_area failed");
		free_xsk_resources(0);
		return -1;
	}
	juice_xsk->umem_area = umem_area;

	// INFO: 在 umem_juice 建立 fill ring & completion ring
	struct xsk_umem_config xsk_umem_cfg;
	memset(&xsk_umem_cfg, 0, sizeof(xsk_umem_cfg));
	xsk_umem_cfg.fill_size = 4096;                     // fill ring
	xsk_umem_cfg.comp_size = 2048;                     // completion ring
	xsk_umem_cfg.frame_size = 2048;                    // UMEM frame size
	xsk_umem_cfg.frame_headroom = XDP_PACKET_HEADROOM; // extra space for each UMEM frame
	struct xsk_umem *umem = NULL;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	if (xsk_umem__create(&umem, umem_area, 4096 * 4096, &fill, &comp, &xsk_umem_cfg)) {
		JLOG_FATAL("PurpleRed: XSK access umem_area failed");
		free_xsk_resources(1);
		return -1;
	}
	juice_xsk->umem = umem;
	juice_xsk->fill = fill;
	juice_xsk->comp = comp;

	// INFO: 建立 AF_XDP socket
	// TODO: 支援多個 queue 的網卡
	struct xsk_socket_config xsk_cfg;
	memset(&xsk_cfg, 0, sizeof(xsk_cfg));
	xsk_cfg.rx_size = 2048; // RX ring
	xsk_cfg.tx_size = 2048; // TX ring
	xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP;
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	if (xsk_socket__create(&xsk, XDP_IFNAME, 0, umem, &rx, &tx, &xsk_cfg)) {
		JLOG_FATAL("PurpleRed: XSK creation failed");
		free_xsk_resources(2);
		return -1;
	}
	juice_xsk->xsk = xsk;
	juice_xsk->rx = rx;
	juice_xsk->tx = tx;
	juice_xsk->xsk_fd = xsk_socket__fd(xsk);

	// INFO: 將 queue_id 和 xsk 更新至 xsk_map
	// TODO: 支援多個 queue 的網卡
	uint32_t queue_id = 0;
	if (bpf_map_update_elem(xsk_map_fd, &queue_id, &(juice_xsk->xsk_fd), 0) != 0) {
		JLOG_FATAL("Failed to bind XSK fd to xsk_map");
		return -1;
	}
	JLOG_INFO("PurpleRed: Added %s queue 0 & XSK fd %d to xsk_map", XDP_IFNAME, juice_xsk->xsk_fd);

	// INFO: 建立一個 thread，專門接收來自 XSK 的封包
	pthread_t tid;
	pthread_create(&tid, NULL, xsk_receive_loop, NULL);
	pthread_detach(tid); // 不必讓其它執行緒呼叫 join

	return 0;
}

// INFO: pthread function
// TODO: 目前為 busy waiting，可改為 sleep waiting 或 polling
void *xsk_receive_loop(void *arg) {
	while (juice_xsk) {
		receive_xsk_packets(juice_packet_handler);
	}

	return NULL;
}

int receive_xsk_packets(void (*packet_handler)(void *packet, int packet_len)) {

	if (!juice_xsk) {
		JLOG_FATAL("PurpleRed: juice_xsk is not exist");
		return -1;
	}

	// INFO: 查看 RX ring (rx) 目前有幾個 UMEM frame descriptor 可接收，從哪裡開始接收
	// TODO: 可調整參數，目前一次最多允許接收 64 個
	unsigned int idx = 0;
	int sum = xsk_ring_cons__peek(&juice_xsk->rx, 64, &idx); // 這次收到的封包數量
	if (!sum) return 0;

	// INFO: 從 rx[idx] 開始取 descriptor (desc)，再從 umem_area 取封包內容，重複 sum 次
	for (int i = 0; i < sum; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&juice_xsk->rx, idx++);
		void *packet = xsk_umem__get_data(juice_xsk->umem_area, desc->addr);
		packet_handler(packet, desc->len);
	}

	xsk_ring_cons__release(&juice_xsk->rx, sum);
	return sum;
}

// INFO: receive_xsk_packets() 每收到一個封包，就會呼叫此函式一次，用來拆解 L2~L4 層
void juice_packet_handler(void *packet, int packet_len) {
	// 以下跟 XDP 程式邏輯幾乎一樣
	struct ethhdr *eth = packet;
	uint16_t eth_proto = ntohs(eth->h_proto);
	struct udphdr *udph;
	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip4h = (void *)(eth + 1);
		udph = (void *)((__u8 *)ip4h + (ip4h->ihl * 4));
	} else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		udph = (void *)(ip6h + 1);
	}
	uint16_t port = ntohs(udph->dest); // 取得 UDP destination port
	// end

	socket_t sock;
	bpf_map_lookup_elem(juice_xsk->wss_map_fd, &port, &sock);
	struct sockaddr_storage addr;
	socklen_t addrlen;
	getsockname(sock, (struct sockaddr *)&addr, &addrlen); // 查詢 sock 綁定的位址，並寫入 addr
	sendto(sock, (void *)(udph + 1), packet + packet_len - (void *)(udph + 1), 0,
	       (struct sockaddr *)&addr, addrlen);
}

int add_to_wss_map(socket_t sock) {
	uint16_t port = udp_get_port(sock);
	int bpf_map_fd = juice_xsk->wss_map_fd;
	// INFO: key 是 port number，value 是 socket file descriptor
	if (bpf_map_update_elem(bpf_map_fd, &port, &sock, BPF_ANY) == 0) {
		JLOG_INFO("PurpleRed: Added socket (fd = %d, port = %hu) to eBPF map", sock, port);
		return 0;
	}

	JLOG_ERROR("PurpleRed: Failed to update eBPF map with port %hu", port);

	return -1;
}

void remove_from_wss_map(socket_t sock) {
	uint16_t port = udp_get_port(sock);
	int bpf_map_fd = juice_xsk->wss_map_fd;
	if (bpf_map_delete_elem(bpf_map_fd, &port) == 0) {
		JLOG_INFO("PurpleRed: Removed port %hu from eBPF map", port);
	}

	JLOG_WARN("PurpleRed: Failed to remove port %hu from eBPF map, errno=%d", port, errno);
}

void free_xsk_resources(int option) {
	switch (option) {
	case 3:
		xsk_socket__delete(juice_xsk->xsk);
	case 2:
		xsk_umem__delete(juice_xsk->umem);
	case 1:
		munmap(juice_xsk->umem_area, 4096 * 4096);
	case 0:
	default:
		free(juice_xsk);
		juice_xsk = NULL;
	}
}

#endif