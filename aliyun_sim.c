// aliyun_sim.c
#include "aliyun_sim.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#endif

static volatile int g_server_running = 0;
static aliyun_sim_conf_t g_conf;

static const char* now_ts() {
	static char buf[32];
	time_t t = time(NULL);
	struct tm tmv;
#ifdef _WIN32
	localtime_s(&tmv, &t);
#else
	localtime_r(&t, &tmv);
#endif
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
	return buf;
}

// 和客户端约定的简化 Token 算法：
// token = hex32( sum(byte(productKey+deviceName+deviceSecret)) ^ 0x5A )
static void make_token_inner(const device_triple_t *triple, char *out, int out_len) {
	unsigned int sum = 0;
	const char *p;
	for (p = triple->product_key; *p; ++p) sum += (unsigned char)(*p);
	for (p = triple->device_name; *p; ++p) sum += (unsigned char)(*p);
	for (p = triple->device_secret; *p; ++p) sum += (unsigned char)(*p);
	unsigned int v = (sum ^ 0x5Au) & 0xFFFFFFFFu;
	snprintf(out, out_len, "%08X", v);
}

void aliyun_make_token(const device_triple_t *triple, char *out, int out_len) {
	make_token_inner(triple, out, out_len);
}

static int parse_coap_basic(const uint8_t *buf, int len,
							 uint8_t *out_type, uint8_t *out_code, uint16_t *out_mid,
							 const uint8_t **out_opt_start, int *out_opt_len,
							 const uint8_t **out_payload, int *out_payload_len) {
	if (len < 4) return -1;
	uint8_t ver = (buf[0] >> 6) & 0x03;
	if (ver != 1) return -2;
	uint8_t tkl = buf[0] & 0x0F;
	int off = 4;
	if (len < off + tkl) return -3;
	*out_type = (buf[0] >> 4) & 0x03;
	*out_code = buf[1];
	*out_mid = (uint16_t)((buf[2] << 8) | buf[3]);
	// 跳过 Token
	off += tkl;
	int opt_start = off;
	// 解析到 payload marker 0xFF 或结束
	while (off < len) {
		if (buf[off] == 0xFF) { // payload marker
			*out_opt_start = buf + opt_start;
			*out_opt_len = off - opt_start;
			*out_payload = buf + off + 1;
			*out_payload_len = len - (off + 1);
			return 0;
		}
		// option header 1 byte + ext
		uint8_t delta = (buf[off] >> 4) & 0x0F;
		uint8_t olen = buf[off] & 0x0F;
		off++;
		if (delta == 13) off++;
		else if (delta == 14) off += 2;
		if (olen == 13) off++;
		else if (olen == 14) off += 2;
		off += olen;
	}
	*out_opt_start = buf + opt_start;
	*out_opt_len = len - opt_start;
	*out_payload = NULL;
	*out_payload_len = 0;
	return 0;
}

static int build_coap_response(uint8_t *out, int cap, uint8_t type, uint8_t code, uint16_t mid) {
	if (cap < 4) return -1;
	out[0] = (uint8_t)((1 << 6) | (type << 4) | 0); // ver=1, tkl=0
	out[1] = code;
	out[2] = (uint8_t)(mid >> 8);
	out[3] = (uint8_t)(mid & 0xFF);
	return 4; // 无 token、无 options、无 payload
}

#ifdef _WIN32
#include <process.h>
static unsigned __stdcall server_thread(void *arg)
#else
#include <pthread.h>
static void* server_thread(void *arg)
#endif
{
	(void)arg;
	socket_t s = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
	if ((int)s < 0) {
		perror("server socket");
#ifdef _WIN32
		return 0;
#else
		return NULL;
#endif
	}
	struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(g_conf.listen_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
#ifdef _WIN32
		closesocket(s);
		return 0;
#else
		close(s);
		return NULL;
#endif
	}

	printf("[%s] 阿里云模拟服务启动，端口 %u\n", now_ts(), g_conf.listen_port);
	uint8_t buf[1500];
	while (g_server_running) {
		struct sockaddr_in from; socklen_t fl = sizeof(from);
		int r = recvfrom(s, (char*)buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
		if (r <= 0) {
			// 继续
			continue;
		}
		uint8_t type, code; uint16_t mid;
		const uint8_t *opt_start, *payload; int opt_len, payload_len;
		if (parse_coap_basic(buf, r, &type, &code, &mid, &opt_start, &opt_len, &payload, &payload_len) != 0) {
			continue;
		}
		// 简化：从 options 中查找 Uri-Query 里的 token=xxxx
		// 这里不完全解析 options 编码，而是直接在 opt 字节流中寻找 "token=" 的 ASCII 片段
		int ok = 0;
		char token_expect[16];
		make_token_inner(&g_conf.triple, token_expect, sizeof(token_expect));
		for (int i = 0; i + 6 < opt_len; ++i) {
			if (opt_start[i] == 't' && i + 12 < opt_len) {
				if (memcmp(opt_start + i, "token=", 6) == 0) {
					if (i + 6 + 8 <= opt_len && memcmp(opt_start + i + 6, token_expect, 8) == 0) {
						ok = 1; break;
					}
				}
			}
		}
		uint8_t resp[64]; int resp_len;
		if (!ok) {
			resp_len = build_coap_response(resp, sizeof(resp), (type==0)?2:2, (uint8_t)((4<<5)|1), mid); // 4.01 Unauthorized
			printf("[%s] 鉴权失败，返回 4.01 (MID=0x%04X)\n", now_ts(), mid);
		} else {
			resp_len = build_coap_response(resp, sizeof(resp), (type==0)?2:2, (uint8_t)((2<<5)|5), mid); // 2.05 Content
			printf("[%s] 已接收上报 (MID=0x%04X), 返回 2.05\n", now_ts(), mid);
		}
		sendto(s, (const char*)resp, resp_len, 0, (struct sockaddr*)&from, fl);
	}

#ifdef _WIN32
	closesocket(s);
	return 0;
#else
	close(s);
	return NULL;
#endif
}

int aliyun_sim_start(const aliyun_sim_conf_t *conf) {
	if (!conf) return -1;
	g_conf = *conf;
	g_server_running = 1;
#ifdef _WIN32
	uintptr_t th = _beginthreadex(NULL, 0, server_thread, NULL, 0, NULL);
	if (th == 0) return -2;
#else
	pthread_t th; if (pthread_create(&th, NULL, server_thread, NULL) != 0) return -2; pthread_detach(th);
#endif
	return 0;
}

void aliyun_sim_stop(void) {
	g_server_running = 0;
}


