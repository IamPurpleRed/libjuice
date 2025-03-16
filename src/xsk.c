#if USE_XDP

#include "xsk.h"
#include "log.h"

#include <bpf/bpf.h>
#include <stdlib.h>
#include <sys/mman.h>

static xsk_socket_info_t *juice_xsk = NULL;

int initialize_xsk() {
	if (juice_xsk)
		return 0; // 已初始化

	juice_xsk = calloc(1, sizeof(xsk_socket_info_t));
	if (!juice_xsk) {
		JLOG_FATAL("PurpleRed: Memory allocation for XSK failed");
		return -1;
	}

	int ifindex = if_nametoindex(XDP_IFNAME);
	if (ifindex == 0) {
		JLOG_FATAL("PurpleRed: XDP_IFNAME not found");
		goto error;
	}

	// INFO: 在 user space 分配 4096 * 4096 Byte 的空間
	void *umem_area = mmap(NULL, 4096 * 4096, PROT_READ | PROT_WRITE,
	                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (umem_area == MAP_FAILED) {
		JLOG_FATAL("PurpleRed: mmap creation failed");
		goto error;
	}
	juice_xsk->umem_area = umem_area;

	// INFO: 在 umem_juice 建立 fill ring & completion ring
	struct xsk_umem_config umem_cfg;
	memset(&umem_cfg, 0, sizeof(umem_cfg));
	umem_cfg.fill_size = 4096;                     // fill ring
	umem_cfg.comp_size = 2048;                     // completion ring
	umem_cfg.frame_size = 2048;                    // UMEM frame size
	umem_cfg.frame_headroom = XDP_PACKET_HEADROOM; // extra space for each UMEM frame
	struct xsk_umem *umem_xsk = NULL;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	if (xsk_umem__create(&umem_xsk, umem_area, 4096 * 4096, &fill, &comp,
	                     &umem_cfg)) {
		JLOG_FATAL("PurpleRed: XSK access umem_juice failed");
		goto error_map;
	}
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
	if (xsk_socket__create(&(juice_xsk->xsk), XDP_IFNAME, 0, umem_xsk, &(juice_xsk->rx),
	                       &(juice_xsk->tx), &xsk_cfg)) {
		JLOG_FATAL("PurpleRed: XSK creation failed");
		goto error_xsk;
	}

	juice_xsk->xsk_fd = xsk_socket__fd(juice_xsk->xsk);

	return 0;

error_xsk:
	xsk_umem__delete(umem_xsk);
error_map:
	munmap(umem_area, 4096 * 4096);
error:
	free(juice_xsk);
	juice_xsk = NULL;
	return -1;
}

int add_port_to_ebpf_map(socket_t sock) {
	uint16_t port = udp_get_port(sock);
	int bpf_map_fd = bpf_obj_get("/sys/fs/bpf/wss_map");
	if (bpf_map_fd >= 0) {
		if (bpf_map_update_elem(bpf_map_fd, &port, &sock, BPF_ANY) == 0) {
			JLOG_INFO("PurpleRed: Added socket (fd = %d, port = %hu) to eBPF map", sock, port);
			return 0;
		}

		JLOG_ERROR("PurpleRed: Failed to update eBPF map with port %hu", port);
	} else {
		JLOG_ERROR("PurpleRed: Failed to get eBPF map");
	}

	return -1;
}

void remove_port_from_ebpf_map(socket_t sock) {
	uint16_t port = udp_get_port(sock);
	int bpf_map_fd = bpf_obj_get("/sys/fs/bpf/webrtc_port_map");
	if (bpf_map_fd >= 0) {
		if (bpf_map_delete_elem(bpf_map_fd, &port) == 0) {
			JLOG_INFO("PurpleRed: Removed port %hu from eBPF map", port);
		}

		JLOG_ERROR("PurpleRed: Failed to remove port %hu from eBPF map, errno=%d", port, errno);
	} else {
		JLOG_ERROR("PurpleRed: Failed to get eBPF map");
	}
}

#endif