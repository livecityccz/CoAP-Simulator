// sensor_sim.h
// DHT11 温湿度数据模拟

#ifndef SENSOR_SIM_H
#define SENSOR_SIM_H

typedef struct {
	float temperature_c;
	float humidity_rh;
	int is_abnormal; // 1 表示异常值
} sensor_reading_t;

// 初始化随机种子
void sensor_sim_init(void);

// 生成一次读数（温度10~35℃，湿度30%~70%，约每20次产生1次异常值）
sensor_reading_t sensor_sim_read(void);

#endif // SENSOR_SIM_H


