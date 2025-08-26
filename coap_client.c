// coap_client.c
// 简易 CoAP 客户端实现（RFC7252 子集）：支持 CON/NON、Token、Uri 选项、MID 自增与重传

#include "coap_client.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

#define COAP_VERSION 1

// CoAP 代码编码：class.xx => (class << 5) | detail
static uint8_t coap_make_code(uint8_t cls, uint8_t detail) {
	return (uint8_t)((cls << 5) | (detail & 0x1F));
}

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

int platform_net_init(void) {
#ifdef _WIN32
	WSADATA wsa;
	return WSAStartup(MAKEWORD(2,2), &wsa);
#else
	return 0;
#endif
}

void platform_net_deinit(void) {
#ifdef _WIN32
	WSACleanup();
#endif
}

static uint16_t next_mid_inc(uint16_t *mid) {
	uint16_t cur = *mid;
	*mid = (uint16_t)(*mid + 1);
	return cur;
}

static int set_recv_timeout(socket_t s, uint32_t ms) {
#ifdef _WIN32
	DWORD tv = ms;
	return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
	struct timeval tv;
	tv.tv_sec = (time_t)(ms / 1000);
	tv.tv_usec = (suseconds_t)((ms % 1000) * 1000);
	return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

int coap_client_init(coap_client_t *client, const coap_client_conf_t *conf) {
	if (!client || !conf) return -1;
	memset(client, 0, sizeof(*client));
	client->conf = *conf;
	client->next_mid = 0;

	client->sock = (socket_t)socket(AF_INET, SOCK_DGRAM, 0);
	if ((int)client->sock < 0) {
		perror("socket");
		return -2;
	}
	memset(&client->server_addr, 0, sizeof(client->server_addr));
	client->server_addr.sin_family = AF_INET;
	client->server_addr.sin_port = htons(conf->server_port);
	if (inet_pton(AF_INET, conf->server_host, &client->server_addr.sin_addr) != 1) {
		perror("inet_pton");
#ifdef _WIN32
		closesocket(client->sock);
#else
		close(client->sock);
#endif
		return -3;
	}
	return 0;
}

void coap_client_close(coap_client_t *client) {
	if (!client) return;
	if ((int)client->sock >= 0) {
#ifdef _WIN32
		closesocket(client->sock);
#else
		close(client->sock);
#endif
	}
}

static size_t encode_uint_option(uint8_t *buf, uint32_t value) {
	// CoAP 整数选项编码：0/1/2/4 字节
	if (value == 0) return 0;
	if (value <= 0xFF) { buf[0] = (uint8_t)value; return 1; }
	if (value <= 0xFFFF) { buf[0]= (value>>8)&0xFF; buf[1]= value & 0xFF; return 2; }
	buf[0] = (value >> 24) & 0xFF;
	buf[1] = (value >> 16) & 0xFF;
	buf[2] = (value >> 8) & 0xFF;
	buf[3] = value & 0xFF;
	return 4;
}

static int add_option(uint8_t *pkt, size_t pkt_cap, size_t *offset,
					 uint16_t *last_opt_num, uint16_t opt_num,
					 const uint8_t *val, size_t val_len) {
	// 计算 Option Delta
	uint16_t delta = (uint16_t)(opt_num - *last_opt_num);
	uint8_t ext_delta_bytes[2]; size_t ext_delta_len = 0;
	uint8_t delta_field = 0;
	if (delta < 13) { delta_field = (uint8_t)delta; }
	else if (delta < 269) { delta_field = 13; ext_delta_bytes[0] = (uint8_t)(delta - 13); ext_delta_len = 1; }
	else { delta_field = 14; uint16_t d = (uint16_t)(delta - 269); ext_delta_bytes[0] = (d>>8)&0xFF; ext_delta_bytes[1] = d&0xFF; ext_delta_len = 2; }

	// 计算 Option Length
	uint8_t ext_len_bytes[2]; size_t ext_len_len = 0;
	uint8_t len_field = 0;
	if (val_len < 13) { len_field = (uint8_t)val_len; }
	else if (val_len < 269) { len_field = 13; ext_len_bytes[0] = (uint8_t)(val_len - 13); ext_len_len = 1; }
	else { len_field = 14; uint16_t l = (uint16_t)(val_len - 269); ext_len_bytes[0] = (l>>8)&0xFF; ext_len_bytes[1] = l&0xFF; ext_len_len = 2; }

	// 头字节
	size_t need = 1 + ext_delta_len + ext_len_len + val_len;
	if (*offset + need > pkt_cap) return -1;
	pkt[(*offset)++] = (uint8_t)((delta_field << 4) | (len_field & 0x0F));
	for (size_t i = 0; i < ext_delta_len; ++i) pkt[(*offset)++] = ext_delta_bytes[i];
	for (size_t i = 0; i < ext_len_len; ++i) pkt[(*offset)++] = ext_len_bytes[i];
	for (size_t i = 0; i < val_len; ++i) pkt[(*offset)++] = val[i];
	*last_opt_num = opt_num;
	return 0;
}

const char* coap_code_to_text(uint8_t code) {
	static char tmp[16];
	uint8_t cls = code >> 5; uint8_t detail = code & 0x1F;
	snprintf(tmp, sizeof(tmp), "%u.%02u", cls, detail);
	return tmp;
}

// 发送并（在 CON 模式）等待 ACK/响应
static int send_and_wait(coap_client_t *client, const uint8_t *buf, size_t len,
						  uint16_t expect_mid, uint8_t expect_type,
						  uint32_t timeout_ms, uint8_t max_retry,
						  uint8_t *out_code) {
	if (client->conf.net_mode == NETWORK_DOWN) {
		printf("[%s] 网络中断，发送丢弃\n", now_ts());
		return -1;
	}

	uint32_t wait_ms = timeout_ms;
	for (uint8_t attempt = 0; ; ++attempt) {
		ssize_t s = sendto(client->sock, (const char*)buf, (int)len, 0,
						 (struct sockaddr*)&client->server_addr, sizeof(client->server_addr));
		if (s < 0) {
			perror("sendto");
			return -2;
		}
		printf("[%s] 已发送 %zu 字节 (MID=0x%04X)\n", now_ts(), len, expect_mid);

		if (client->conf.msg_type == COAP_TYPE_NON) {
			// 非确认消息，不等待
			return 0;
		}

		set_recv_timeout(client->sock, client->conf.net_mode == NETWORK_TIMEOUT ? 10 : wait_ms);
		uint8_t rbuf[1152];
		struct sockaddr_in from; socklen_t flen = sizeof(from);
		ssize_t r = recvfrom(client->sock, (char*)rbuf, sizeof(rbuf), 0, (struct sockaddr*)&from, &flen);
		if (r <= 0) {
			if (client->conf.net_mode == NETWORK_TIMEOUT) {
				printf("[%s] 超时未收到响应 (模拟)\n", now_ts());
			} else {
				printf("[%s] 超时未收到响应\n", now_ts());
			}
			if (attempt >= max_retry) return -3; // 放弃
			wait_ms *= 2; // 指数退避
			continue; // 重传
		}

		// 解析最小头部
		if (r < 4) { printf("[%s] 响应长度过短\n", now_ts()); return -4; }
		uint8_t ver = (rbuf[0] >> 6) & 0x03;
		uint8_t type = (rbuf[0] >> 4) & 0x03;
		uint8_t tkl = rbuf[0] & 0x0F;
		uint8_t code = rbuf[1];
		uint16_t mid = (uint16_t)((rbuf[2] << 8) | rbuf[3]);
		if (ver != COAP_VERSION) { printf("[%s] 响应版本错误\n", now_ts()); return -5; }
		if (mid != expect_mid) { printf("[%s] 响应 MID 不匹配\n", now_ts()); return -6; }
		if (type != expect_type && type != 2 /* ACK */) {
			printf("[%s] 响应类型不匹配\n", now_ts());
			return -7;
		}
		if (out_code) *out_code = code;
		printf("[%s] 收到响应 code=%s (0x%02X)\n", now_ts(), coap_code_to_text(code), code);
		return 0;
	}
}

int coap_client_post_json(
	coap_client_t *client,
	const char *uri_host,
	const char *uri_path,
	const char *uri_query,
	const char *json_payload,
	uint16_t *out_message_id
) {
	if (!client || !json_payload) return -1;

	uint8_t pkt[1152]; size_t off = 0; uint16_t last_opt = 0;
	uint8_t token[4] = {0xA1,0xB2,0xC3,0xD4};
	uint8_t tkl = sizeof(token);
	uint16_t mid = next_mid_inc(&client->next_mid);
	if (out_message_id) *out_message_id = mid;

	// Header
	uint8_t ver_type_tkl = (uint8_t)((COAP_VERSION << 6) | ((client->conf.msg_type & 0x03) << 4) | (tkl & 0x0F));
	uint8_t code = coap_make_code(0, 02); // 0.02 POST
	pkt[off++] = ver_type_tkl;
	pkt[off++] = code;
	pkt[off++] = (uint8_t)((mid >> 8) & 0xFF);
	pkt[off++] = (uint8_t)(mid & 0xFF);

	// Token
	for (size_t i = 0; i < tkl; ++i) pkt[off++] = token[i];

	// Options (Uri-Host=3, Uri-Path=11, Uri-Query=15, Content-Format=12)
	if (uri_host && *uri_host) {
		add_option(pkt, sizeof(pkt), &off, &last_opt, 3, (const uint8_t*)uri_host, strlen(uri_host));
	}
	if (uri_path && *uri_path) {
		add_option(pkt, sizeof(pkt), &off, &last_opt, 11, (const uint8_t*)uri_path, strlen(uri_path));
	}
	if (uri_query && *uri_query) {
		add_option(pkt, sizeof(pkt), &off, &last_opt, 15, (const uint8_t*)uri_query, strlen(uri_query));
	}
	// Content-Format: application/json (50)
	{
		uint8_t fmtbuf[4]; size_t fmtn = encode_uint_option(fmtbuf, 50);
		add_option(pkt, sizeof(pkt), &off, &last_opt, 12, fmtbuf, fmtn);
	}

	// Payload Marker
	pkt[off++] = 0xFF;
	// Payload
	size_t payload_len = strlen(json_payload);
	if (off + payload_len > sizeof(pkt)) return -2;
	memcpy(pkt + off, json_payload, payload_len);
	off += payload_len;

	uint8_t resp_code = 0;
	int rc = send_and_wait(client, pkt, off, mid,
		client->conf.msg_type == COAP_TYPE_CON ? 2 /* ACK */ : 1 /* NON */,
		client->conf.ack_timeout_ms, client->conf.max_retransmit, &resp_code);
	return rc;
}


