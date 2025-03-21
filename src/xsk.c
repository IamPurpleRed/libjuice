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

#define FRAME_SIZE 2048
#define FILL_RING_SIZE 4096

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
	int wss_map_fd = bpf_obj_get("/sys/fs/bpf/wss_map");
	if (wss_map_fd < 0) {
		JLOG_FATAL("PurpleRed: Failed to get wss_map");
		return -1;
	}
	juice_xsk->wss_map_fd = wss_map_fd;

	// INFO: 尋找 xsk_map 的 file descriptor
	int xsk_map_fd = bpf_obj_get("/sys/fs/bpf/xsk_map");
	if (xsk_map_fd < 0) {
		JLOG_FATAL("PurpleRed: Failed to get xsk_map");
		return -1;
	}
	juice_xsk->xsk_map_fd = xsk_map_fd;

	// int ifindex = if_nametoindex(XDP_IFNAME);
	// if (ifindex == 0) {
	// 	JLOG_FATAL("PurpleRed: XDP_IFNAME not found");
	// 	free_xsk_resources(0);
	// 	return -1;
	// }

	// INFO: 在 user space 分配 4096 * 4096 Byte 的空間
	void *umem_area = mmap(NULL, 4096 * 4096, PROT_READ | PROT_WRITE,
	                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (umem_area == MAP_FAILED) {
		JLOG_FATAL("PurpleRed: Memory allocation for umem_area failed");
		free_xsk_resources(0);
		return -1;
	}
	juice_xsk->umem_area = umem_area;

	// INFO: 建立 fill ring & completion ring
	struct xsk_umem_config xsk_umem_cfg;
	memset(&xsk_umem_cfg, 0, sizeof(xsk_umem_cfg));
	xsk_umem_cfg.fill_size = FILL_RING_SIZE;           // fill ring
	xsk_umem_cfg.comp_size = 2048;                     // completion ring
	xsk_umem_cfg.frame_size = FRAME_SIZE;              // UMEM frame size
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
	// FUTURE: 支援多個 queue 的網卡
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

	// INFO: 將 queue_id 和 xsk 寫入 xsk_map -> 綁定
	// FUTURE: 支援多個 queue 的網卡
	int queue_id = 0;
	if (bpf_map_update_elem(xsk_map_fd, &queue_id, &(juice_xsk->xsk_fd), BPF_ANY) != 0) {
		JLOG_FATAL("PurpleRed: Failed to bind XSK fd to xsk_map");
		free_xsk_resources(3);
		return -1;
	}

	// INFO: 將可用的 UMEM frame index 放入 fill queue，讓 kernel 知道哪些 index 可以放置從 XSK 來的封包
	prime_fill_ring(&(juice_xsk->fill));

	// INFO: 建立一個 thread，專門接收來自 XSK 的封包
	pthread_t tid;
	pthread_create(&tid, NULL, xsk_receive_loop, NULL);
	pthread_detach(tid); // 不必讓其它執行緒呼叫 join

	return 0;
}


// TODO: 只能收 4096 個 frame
void prime_fill_ring(struct xsk_ring_prod *fill) {
	uint32_t idx;
	int ret;

	int frames_to_add = FILL_RING_SIZE;

	// while (frames_to_add > 0) {
		// 請求 fill ring，看看是否有足夠空位能塞 frames_to_add 個「frame offset」
		ret = xsk_ring_prod__reserve(fill, frames_to_add, &idx);
		if (ret != frames_to_add) {
			// 表示 fill ring 現在還不能一次容納全部 frames_to_add
			// 這裡可以先塞 ret 個，然後再繼續迴圈，或 sleep 後重試
			// 先示範簡單作法：就先塞 ret 個
			frames_to_add -= ret;
		}

		// ret 可能是 >= 0 的數值，如果 ret=0，表示根本reserve不到，可能要再跑迴圈
		for (int i = 0; i < ret; i++) {
			// 塞入 frame offset (相對於 umem_area 的位移量)
			// 假設把 frame i 對應到 offset = i * FRAME_SIZE
			// 也可能要用 (base_index + i) 來計算，視你要如何管理 frames
			*xsk_ring_prod__fill_addr(fill, idx + i) = (i * FRAME_SIZE);
		}

		// 告訴核心，我們這次總共「提交」了 ret 個可用 frame
		xsk_ring_prod__submit(fill, ret);
	    JLOG_INFO("PurpleRed: Prime %d frames to fill ring", ret);

	    // 全部提交完就跳出
		// if (ret > 0 && ret == frames_to_add + ret) {
		// 	frames_to_add = 0;
		// }
	// }
}


// INFO: pthread function (busy waiting)
void *xsk_receive_loop(void *arg) {
	while (juice_xsk) {
		receive_xsk_packets();
	}

	return NULL;
}


int receive_xsk_packets() {
	if (!juice_xsk) {
		JLOG_FATAL("PurpleRed: juice_xsk is not exist");
		return -1;
	}

	// INFO: 首先查看 RX ring (rx) 目前有幾個 UMEM frame descriptor 可接收，從哪裡開始接收
	unsigned int idx = 0;
	int sum = xsk_ring_cons__peek(&juice_xsk->rx, 64, &idx); // 這次收到的封包數量
	if (!sum) return 0;
	JLOG_INFO("PurpleRed: Received %d packets", sum);

	// INFO: 從 rx[idx] 開始取 descriptor (desc)，再從 umem_area 取封包內容，重複 sum 次
	for (int i = 0; i < sum; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&juice_xsk->rx, idx++);
		void *packet = xsk_umem__get_data(juice_xsk->umem_area, desc->addr);
		packet_handler(packet, desc->len);
	}

	xsk_ring_cons__release(&juice_xsk->rx, sum);
	return sum;
}


// INFO: 從 RX ring 取一個封包，回傳長度，若沒有則回傳 -1
// FUTURE: 一次接收多個封包，目前 sum 非 0 即 1，等於原本的 recvfrom()
// int receive_xsk_packet(char *buffer, addr_record_t *src) {
// 	if (!juice_xsk) {
// 		JLOG_FATAL("PurpleRed: juice_xsk is not exist");
// 		return -1;
// 	}
// 	// INFO: 首先查看 RX ring (rx) 目前有幾個 UMEM frame descriptor 可接收，從哪裡開始接收
// 	unsigned int idx = 0;
// 	int sum = xsk_ring_cons__peek(&juice_xsk->rx, 1, &idx);
// 	if (!sum) return -1;
// 	JLOG_DEBUG("PurpleRed: peek");
// 	// INFO: 從 rx[idx] 開始取 descriptor (desc)，再從 umem_area 取封包內容，重複 sum 次
// 	int *len;
// 	for (int i = 0; i < sum; i++) {
// 		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&juice_xsk->rx, idx++);
// 		void *packet = xsk_umem__get_data(juice_xsk->umem_area, desc->addr);
// 		packet_handler(packet, desc->len, buffer, len, src);
// 	}
// 	xsk_ring_cons__release(&juice_xsk->rx, sum);
// 	return len;
// }


// INFO: receive_xsk_packets() 每收到一個封包，就會呼叫此函式一次，用來拆解 L2~L4 層
void packet_handler(void *packet, int packet_len) {
	wss_value_t value;
	memset(&value, 0, sizeof(value));
	// 以下跟 XDP 程式邏輯幾乎一樣
	struct ethhdr *eth = packet;
	uint16_t eth_proto = ntohs(eth->h_proto);
	struct udphdr *udph;
	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip4h = (void *)(eth + 1);
		udph = (void *)((__u8 *)ip4h + (ip4h->ihl * 4));
		value.ip_version = 4;
		value.src_ipv4 = ip4h->saddr;
	} else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		udph = (void *)(ip6h + 1);
		value.ip_version = 6;
		memcpy(&(value.src_ipv6), &(ip6h->saddr), 16);
	}
	value.src_port = ntohs(udph->source);  // src port
	uint16_t dest_port = ntohs(udph->dest); // dest port
	// end

	// INFO: 判斷是否要更新 wss_map[dest]（包含 src IP & port）
	wss_value_t old_value;
	bpf_map_lookup_elem(juice_xsk->wss_map_fd, &dest_port, &old_value);
	value.socket_fd = old_value.socket_fd; // 從 old_value 取出 socket fd
	if (old_value.ip_version == 0) {
		bpf_map_update_elem(juice_xsk->wss_map_fd, &dest_port, &value, BPF_ANY);  // 寫入 value，覆寫 old_value
	}

	// INFO: 自己傳給自己（笨方法）
	struct sockaddr_storage addr;
	socklen_t addrlen;
	getsockname(value.socket_fd, (struct sockaddr *)&addr, &addrlen); // 查詢 sock 綁定的位址，並寫入 addr
	sendto(value.socket_fd, (void *)(udph + 1), packet + packet_len - (void *)(udph + 1), 0,
	       (struct sockaddr *)&addr, addrlen);
}


// INFO: 寫入新的 port 和 socket fd 至 wss_map（不含 src IP & port）
int add_port_to_wss_map(socket_t sock) {
	uint16_t port = udp_get_port(sock);
	wss_value_t value;
	memset(&value, 0, sizeof(value));
	value.socket_fd = sock;
	if (bpf_map_update_elem(juice_xsk->wss_map_fd, &port, &value, BPF_ANY) == 0) {
		JLOG_INFO("PurpleRed: XDP will redirect all packets sent to port %hu to socket (fd = %d)",
		          port, sock);
		return 0;
	}

	JLOG_ERROR("PurpleRed: Failed to update eBPF map with port %hu", port);

	return -1;
}


void remove_from_wss_map(socket_t sock) {
	uint16_t port = udp_get_port(sock);
	int wss_map_fd = juice_xsk->wss_map_fd;
	if (bpf_map_delete_elem(wss_map_fd, &port) == 0) {
		JLOG_INFO("PurpleRed: Removed port %hu from wss_map", port);
	}

	JLOG_WARN("PurpleRed: Failed to remove port %hu from WSS_map", port);
}

void update_src_addr(socket_t sock, addr_record_t *src) {
	uint16_t port = udp_get_port(sock);
	wss_value_t value;
	bpf_map_lookup_elem(juice_xsk->wss_map_fd, &port, &value);
	if (value.ip_version == 4) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&(src->addr);
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(value.src_port); // 必須轉為 network byte order
		addr4->sin_addr.s_addr = value.src_ipv4; // ipv4 已是 network byte order
	} else if (value.ip_version == 6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&(src->addr);
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(value.src_port);             // 必須轉為 network byte order
		memcpy(addr6->sin6_addr.s6_addr, value.src_ipv6, 16); // ipv6 已是 network byte order
	}
	src->len = sizeof(src->addr);
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