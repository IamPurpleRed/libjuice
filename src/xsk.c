#if USE_XDP

#include "xsk.h"
#include "log.h"
#include "conn.h"

#include <bpf/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <socket.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <time.h>    // EXPERIMENT
#include <unistd.h>

#define FRAME_SIZE 2048
#define FILL_RING_SIZE 4096

void prime_fill_ring(struct xsk_ring_prod *fill);
void packet_handler(xdp_info_t *juice_xdp, void *packet, int packet_len);

int initialize_juice_xdp(xdp_info_t **juice_xdp_ptr) {
	if (*juice_xdp_ptr)
		return 0; // 已初始化

	*juice_xdp_ptr = calloc(1, sizeof(xdp_info_t));
	if (!juice_xdp_ptr) {
		JLOG_FATAL("PurpleRed: Memory allocation for conn_registry_t->juice_xdp failed");
		return -1;
	}
	xdp_info_t *juice_xdp = *juice_xdp_ptr;

	// INFO: 尋找 wss_map 的 file descriptor
	int wss_map_fd = bpf_obj_get("/sys/fs/bpf/wss_map");
	if (wss_map_fd < 0) {
		JLOG_FATAL("PurpleRed: Failed to get wss_map");
		juice_xdp_cleanup(juice_xdp, 0);
		return -1;
	}
	juice_xdp->wss_map_fd = wss_map_fd;

	// INFO: 尋找 xsk_map 的 file descriptor
	int xsk_map_fd = bpf_obj_get("/sys/fs/bpf/xsk_map");
	if (xsk_map_fd < 0) {
		JLOG_FATAL("PurpleRed: Failed to get xsk_map");
		juice_xdp_cleanup(juice_xdp, 0);
		return -1;
	}
	juice_xdp->xsk_map_fd = xsk_map_fd;

	// INFO: 在 user space 分配 4096 * 4096 Byte 的空間
	void *umem_area = mmap(NULL, 4096 * 4096, PROT_READ | PROT_WRITE,
	                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (umem_area == MAP_FAILED) {
		JLOG_FATAL("PurpleRed: Memory allocation for umem_area failed");
		juice_xdp_cleanup(juice_xdp, 0);
		return -1;
	}
	juice_xdp->umem_area = umem_area;

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
		juice_xdp_cleanup(juice_xdp, 1);
		return -1;
	}
	juice_xdp->umem = umem;
	juice_xdp->fill = fill;
	juice_xdp->comp = comp;

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
		juice_xdp_cleanup(juice_xdp, 2);
		return -1;
	}
	juice_xdp->xsk = xsk;
	juice_xdp->rx = rx;
	juice_xdp->tx = tx;
	juice_xdp->xsk_fd = xsk_socket__fd(xsk);

	// INFO: 將 queue_id 和 xsk 寫入 xsk_map -> 綁定
	// FUTURE: 支援多個 queue 的網卡
	int queue_id = 0;
	if (bpf_map_update_elem(xsk_map_fd, &queue_id, &(juice_xdp->xsk_fd), BPF_ANY) != 0) {
		JLOG_FATAL("PurpleRed: Failed to bind XSK fd to xsk_map");
		juice_xdp_cleanup(juice_xdp, 3);
		return -1;
	}

	// INFO: 將可用的 UMEM frame index 放入 fill queue，讓 kernel 知道哪些 index 可以放置從 XSK 來的封包
	prime_fill_ring(&(juice_xdp->fill));

	return 0;
}

void juice_xdp_cleanup(xdp_info_t *juice_xdp, int option) {
	switch (option) {
	case 3:
		xsk_socket__delete(juice_xdp->xsk);
	case 2:
		xsk_umem__delete(juice_xdp->umem);
	case 1:
		munmap(juice_xdp->umem_area, 4096 * 4096);
	case 0:
	default:
		free(juice_xdp);
	}
}

int initialize_recv_rb(xdp_agent_rb_t **recv_rb_ptr) {
	if (*recv_rb_ptr)
		return 0; // 已初始化

	*recv_rb_ptr = calloc(1, sizeof(xdp_agent_rb_t));
	if (!recv_rb_ptr) {
		JLOG_FATAL("PurpleRed: Memory allocation for conn_impl_t->recv_rb failed");
		return -1;
	}
	xdp_agent_rb_t *recv_rb = *recv_rb_ptr;

	recv_rb->efd = eventfd(0, EFD_NONBLOCK);
	if (recv_rb->efd < 0) {
		JLOG_FATAL("PurpleRed: recv_rb->efd creation failed");
		free(recv_rb);
		return -1;
	}

	memset(recv_rb->buffer, 0, sizeof(recv_rb->buffer));
	atomic_init(&(recv_rb->head), 0);
	atomic_init(&(recv_rb->tail), 0);

	return 0;
}

void recv_rb_cleanup(xdp_agent_rb_t *recv_rb) {}

// INFO: 新增 wss_map[port] = xdp_agent_rb_t 的位址
int add_port_to_wss_map(xdp_info_t *juice_xdp, socket_t sock, xdp_agent_rb_t *ptr) {
	uint16_t port = udp_get_port(sock);
	__u64 value = (__u64)(uintptr_t)ptr;  // uintptr_t: 安全的將指標轉型成整數
	if (bpf_map_update_elem(juice_xdp->wss_map_fd, &port, &value, BPF_ANY) == 0) {
		JLOG_INFO("PurpleRed: XDP will redirect all packets sent to port %hu", port);
		return 0;
	}

	JLOG_ERROR("PurpleRed: Failed to update eBPF map with port %hu", port);

	return -1;
}

void remove_port_from_wss_map(socket_t sock, xdp_info_t *juice_xdp) {
	uint16_t port = udp_get_port(sock);
	int wss_map_fd = juice_xdp->wss_map_fd;
	if (bpf_map_delete_elem(wss_map_fd, &port) == 0) {
		JLOG_INFO("PurpleRed: Removed port %hu from wss_map", port);
	}

	JLOG_WARN("PurpleRed: Failed to remove port %hu from wss_map", port);
}

int receive_xsk_packets(xdp_info_t *juice_xdp) {
	if (!juice_xdp) {
		JLOG_FATAL("PurpleRed: juice_xdp is not exist");
		return -1;
	}

	// INFO: 首先查看 RX ring (rx) 目前有幾個 UMEM frame descriptor 可接收，從哪裡開始接收
	unsigned int idx = 0;
	int sum = xsk_ring_cons__peek(&juice_xdp->rx, 64, &idx); // 這次收到的封包數量
	if (!sum) return 0;

	// INFO: 從 rx[idx] 開始取 descriptor (desc)，再從 umem_area 取封包內容，重複 sum 次
	for (int i = 0; i < sum; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&juice_xdp->rx, idx++);
		void *packet = xsk_umem__get_data(juice_xdp->umem_area, desc->addr);
		packet_handler(juice_xdp, packet, desc->len);
	}

	xsk_ring_cons__release(&juice_xdp->rx, sum);
	return sum;
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

// INFO: receive_xsk_packets() 每收到一個封包，就會呼叫此函式一次，用來拆解 wss_metadata_t
void packet_handler(xdp_info_t *juice_xdp, void *raw_pkt, int raw_pkt_len) {
	// EXPERIMENT: timestamp3
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	// EXPERIMENT END

	// 尋找 wss_metadata_t (raw_pkt 的最前面)
	wss_metadata_t *metadata = (wss_metadata_t *)raw_pkt;

	// 解析 xdp_agent_rb_ptr，判斷 rb 是否已滿，如果滿了就 drop 不處理
	xdp_agent_rb_t *rb = (xdp_agent_rb_t *)(uintptr_t)(metadata->xdp_agent_rb_ptr);
	unsigned int tail = atomic_load_explicit(&(rb->tail), memory_order_relaxed);
	unsigned int next = (tail + 1) & 1023;
	unsigned int head = atomic_load_explicit(&(rb->head), memory_order_acquire);
	if (next == head) return; // drop

	// 建立一個 addr_record_t，以放入 wss_metadata_t 的其它內容
	addr_record_t *src = malloc(sizeof(addr_record_t));
	memset(src, 0, sizeof(addr_record_t));
	if (metadata->src_ip_version == 4) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&(src->addr);
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = metadata->src_ipv4;  // network byte order
		addr4->sin_port = metadata->src_port;         // network byte order
		src->len = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&(src->addr);
		addr6->sin6_family = AF_INET6;
		memcpy(addr6->sin6_addr.s6_addr, &(metadata->src_ipv6), 16);  // network byte order
		addr6->sin6_port = metadata->src_port;                        // network byte order
		src->len = sizeof(struct sockaddr_in6);
	}

	// 寫入 xdp_agent_rb，並更新 tail
	agent_recv_t recv_data = {
		.ts3 = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec, // EXPERIMENT: 紀錄 timestamp3
	    .payload_len = raw_pkt_len - sizeof(wss_metadata_t),
	    .payload = (void *)(metadata + 1),
	    .src = src
	};
	rb->buffer[tail] = recv_data;
	atomic_store_explicit(&(rb->tail), next, memory_order_release);

	// 寫入 efd 通知 consumer
	uint64_t inc = 1;
	write(rb->efd, &inc, sizeof(inc));
}

// INFO: 從 RX ring 取一個封包，回傳長度，若沒有則回傳 -1
// FUTURE: 一次接收多個封包，目前 sum 非 0 即 1，等於原本的 recvfrom()
// int receive_xsk_packet(char *buffer, addr_record_t *src) {
// 	if (!juice_xdp) {
// 		JLOG_FATAL("PurpleRed: juice_xdp is not exist");
// 		return -1;
// 	}
// 	// INFO: 首先查看 RX ring (rx) 目前有幾個 UMEM frame descriptor 可接收，從哪裡開始接收
// 	unsigned int idx = 0;
// 	int sum = xsk_ring_cons__peek(&juice_xdp->rx, 1, &idx);
// 	if (!sum) return -1;
// 	JLOG_DEBUG("PurpleRed: peek");
// 	// INFO: 從 rx[idx] 開始取 descriptor (desc)，再從 umem_area 取封包內容，重複 sum 次
// 	int *len;
// 	for (int i = 0; i < sum; i++) {
// 		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&juice_xdp->rx, idx++);
// 		void *packet = xsk_umem__get_data(juice_xdp->umem_area, desc->addr);
// 		packet_handler(packet, desc->len, buffer, len, src);
// 	}
// 	xsk_ring_cons__release(&juice_xdp->rx, sum);
// 	return len;
// }

#endif