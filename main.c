// main.c
// 传感器→CoAP 客户端→阿里云模拟服务 交互演示

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "coap_client.h"
#include "sensor_sim.h"
#include "aliyun_sim.h"

#ifdef _WIN32
#include <windows.h>
#endif

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

static void sleep_sec(int s) {
#ifdef _WIN32
	Sleep(s * 1000);
#else
	sleep(s);
#endif
}

static void enable_utf8_console(void) {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
#endif
}

static void make_token_client(const device_triple_t *triple, char *out, int out_len) {
	unsigned int sum = 0; const char *p;
	for (p = triple->product_key; *p; ++p) sum += (unsigned char)(*p);
	for (p = triple->device_name; *p; ++p) sum += (unsigned char)(*p);
	for (p = triple->device_secret; *p; ++p) sum += (unsigned char)(*p);
	unsigned int v = (sum ^ 0x5Au) & 0xFFFFFFFFu;
	snprintf(out, out_len, "%08X", v);
}

static void usage(const char *exe) {
	printf("用法: %s --period N --net [ok|timeout|down] --type [con|non]\n", exe);
	printf("示例: %s --period 2 --net ok --type con\n", exe);
}

int main(int argc, char **argv) {
	int period = 2; // 秒
	network_mode_t net = NETWORK_OK;
	coap_msg_type_t mtype = COAP_TYPE_CON;

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--period") == 0 && i + 1 < argc) {
			period = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--net") == 0 && i + 1 < argc) {
			const char *v = argv[++i];
			if (strcmp(v, "ok") == 0) net = NETWORK_OK;
			else if (strcmp(v, "timeout") == 0) net = NETWORK_TIMEOUT;
			else if (strcmp(v, "down") == 0) net = NETWORK_DOWN;
			else { usage(argv[0]); return 1; }
		} else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
			const char *v = argv[++i];
			if (strcmp(v, "con") == 0) mtype = COAP_TYPE_CON;
			else if (strcmp(v, "non") == 0) mtype = COAP_TYPE_NON;
			else { usage(argv[0]); return 1; }
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]); return 0;
		}
	}

	if (platform_net_init() != 0) {
		printf("网络栈初始化失败\n");
		return 1;
	}

	enable_utf8_console();

	// 启动阿里云模拟服务
	aliyun_sim_conf_t scfg;
	scfg.listen_port = 5683;
	memset(&scfg.triple, 0, sizeof(scfg.triple));
	strcpy(scfg.triple.product_key, "a1b2c3d4");
	strcpy(scfg.triple.device_name, "dev001");
	strcpy(scfg.triple.device_secret, "secret123");
	if (aliyun_sim_start(&scfg) != 0) {
		printf("无法启动阿里云模拟服务\n");
		platform_net_deinit();
		return 1;
	}

	// 客户端
	coap_client_conf_t cconf;
	memset(&cconf, 0, sizeof(cconf));
	strcpy(cconf.server_host, "127.0.0.1");
	cconf.server_port = scfg.listen_port;
	cconf.msg_type = mtype;
	cconf.ack_timeout_ms = 1000; // 1s 起始
	cconf.max_retransmit = 3;
	cconf.net_mode = net;

	coap_client_t client;
	if (coap_client_init(&client, &cconf) != 0) {
		printf("初始化 CoAP 客户端失败\n");
		platform_net_deinit();
		return 1;
	}

	sensor_sim_init();
	device_triple_t triple = scfg.triple;
	char token[16]; make_token_client(&triple, token, sizeof(token));

	printf("[%s] 启动上报：period=%ds, net=%d, type=%s\n", now_ts(), period, net, mtype==COAP_TYPE_CON?"CON":"NON");

	for (int loop = 0; loop < 20; ++loop) {
		sensor_reading_t r = sensor_sim_read();
		char json[128];
		snprintf(json, sizeof(json), "{\"temp\":%.1f,\"humidity\":%.1f,\"abn\":%d}", r.temperature_c, r.humidity_rh, r.is_abnormal);
		char query[128];
		snprintf(query, sizeof(query), "token=%s", token);
		uint16_t mid = 0;
		int rc = coap_client_post_json(&client, "localhost", "things/upload", query, json, &mid);
		if (rc == 0) {
			printf("[%s] 发送: temp=%.1f, humidity=%.1f -> 状态: 成功 (消息ID: 0x%04X)\n", now_ts(), r.temperature_c, r.humidity_rh, mid);
		} else {
			printf("[%s] 发送: temp=%.1f, humidity=%.1f -> 状态: 失败 rc=%d (消息ID: 0x%04X)\n", now_ts(), r.temperature_c, r.humidity_rh, rc, mid);
		}
		sleep_sec(period);
	}

	coap_client_close(&client);
	aliyun_sim_stop();
	platform_net_deinit();
	return 0;
}


