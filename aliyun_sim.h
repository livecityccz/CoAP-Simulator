// aliyun_sim.h
// 本地模拟阿里云 CoAP 接入点（简化）

#ifndef ALIYUN_SIM_H
#define ALIYUN_SIM_H

#include <stdint.h>

typedef struct {
	char product_key[64];
	char device_name[64];
	char device_secret[64];
} device_triple_t;

typedef struct {
	unsigned short listen_port; // 例如 5683
	device_triple_t triple;     // 服务端保存的一份，用于验证
} aliyun_sim_conf_t;

// 在独立线程中启动 UDP CoAP 服务器；返回 0 成功
int aliyun_sim_start(const aliyun_sim_conf_t *conf);

// 停止服务器（本示例用全局开关实现）
void aliyun_sim_stop(void);

// 基于设备三元组生成简化 Token（与客户端保持相同算法）
void aliyun_make_token(const device_triple_t *triple, char *out, int out_len);

#endif // ALIYUN_SIM_H


