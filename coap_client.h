// coap_client.h
// 简易 CoAP 客户端实现（RFC7252 子集）：支持 CON/NON、Token、Uri 选项、MID 自增与重传
// 不依赖第三方库，支持 Windows 与 POSIX

#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	COAP_TYPE_CON = 0,
	COAP_TYPE_NON = 1
} coap_msg_type_t;

typedef enum {
	NETWORK_OK = 0,
	NETWORK_TIMEOUT = 1,
	NETWORK_DOWN = 2
} network_mode_t;

typedef struct {
	char server_host[128]; // 例如 "127.0.0.1"
	uint16_t server_port;  // 例如 5683
	coap_msg_type_t msg_type;
	uint32_t ack_timeout_ms;   // 初始超时时间（重传以指数退避）
	uint8_t max_retransmit;    // 最大重传次数（不含首次）
	network_mode_t net_mode;   // 网络模拟
} coap_client_conf_t;

typedef struct {
	socket_t sock;
	struct sockaddr_in server_addr;
	uint16_t next_mid; // 消息ID 0..65535 循环
	coap_client_conf_t conf;
} coap_client_t;

// 初始化/反初始化 socket 环境（Windows 需要）
int platform_net_init(void);
void platform_net_deinit(void);

// 创建/销毁客户端
int coap_client_init(coap_client_t *client, const coap_client_conf_t *conf);
void coap_client_close(coap_client_t *client);

// 发送一条带 JSON 负载的 POST 请求，带 Uri-Host/Path/Query 选项
// 返回 0 表示成功收到 2.05（Content）或 2.01/2.04（此处统一当成功），>0 表示服务端 4.xx/5.xx，<0 表示失败
int coap_client_post_json(
	coap_client_t *client,
	const char *uri_host,
	const char *uri_path,
	const char *uri_query,
	const char *json_payload,
	uint16_t *out_message_id
);

// 获取可读的响应码文本
const char* coap_code_to_text(uint8_t code);

#ifdef __cplusplus
}
#endif

#endif // COAP_CLIENT_H


