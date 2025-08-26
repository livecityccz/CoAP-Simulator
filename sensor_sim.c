// sensor_sim.c
#include "sensor_sim.h"
#include <stdlib.h>
#include <time.h>

static int abnormal_counter = 0;

void sensor_sim_init(void) {
	unsigned int seed = (unsigned int)time(NULL);
	srand(seed);
	abnormal_counter = 0;
}

static float frand_range(float minv, float maxv) {
	float r = (float)rand() / (float)RAND_MAX;
	return minv + r * (maxv - minv);
}

sensor_reading_t sensor_sim_read(void) {
	sensor_reading_t r;
	r.is_abnormal = 0;
	// 约每 20 次触发一次异常
	if ((rand() % 20) == 0) {
		r.temperature_c = frand_range(-10.0f, 80.0f);
		r.humidity_rh = frand_range(-5.0f, 110.0f);
		r.is_abnormal = 1;
		return r;
	}
	// 正常范围
	r.temperature_c = frand_range(10.0f, 35.0f);
	r.humidity_rh = frand_range(30.0f, 70.0f);
	return r;
}


