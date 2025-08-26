## CoAP 传感器模拟器

基于C实现的CoAP端到端模拟器：随机生成温湿度数据，通过 CoAP 协议上报到本地模拟的“阿里云 CoAP 接入点”。支持 CON/NON、消息 ID 自增、CON 超时重传、Uri-Host/Path/Query 选项与 JSON 负载。可模拟网络正常、超时、断开三种状态。

### 目录结构

- `main.c`：程序入口，参数解析，启动服务端线程与客户端上报流程
- `coap_client.c/.h`：CoAP 客户端打包、发送与（CON）重传逻辑
- `aliyun_sim.c/.h`：本地“阿里云”模拟服务端（UDP 5683），校验 token 并回 2.05/4.01
- `sensor_sim.c/.h`：DHT11 数据模拟，偶发异常值

### 编译

Windows（MinGW/TDM-GCC）：
```bash
gcc -O2 -o coap_demo.exe main.c coap_client.c sensor_sim.c aliyun_sim.c -lws2_32
```

Linux / macOS：
```bash
gcc -O2 -o coap_demo main.c coap_client.c sensor_sim.c aliyun_sim.c
```

### 运行参数

- `--period N`：采集/上报周期（秒），默认 2
- `--net [ok|timeout|down]`：网络状态模拟
  - `ok`：正常网络
  - `timeout`：收不到响应（用于 CON 重传演示）
  - `down`：网络中断（发送直接失败）
- `--type [con|non]`：CoAP 消息类型
  - `con`：确认消息，等待 ACK/响应，带超时重传（指数退避）
  - `non`：非确认消息，不等待响应
- `-h/--help`：查看帮助

示例（Windows）：
```bash
coap_demo.exe --period 2 --net ok --type con
```

示例（Linux/macOS）：
```bash
./coap_demo --period 2 --net ok --type con
```

### 预期日志

程序启动后会先启动本地模拟服务端（UDP 5683），随后客户端按周期上报：

```text
[2025-08-26 12:00:00] 阿里云模拟服务启动，端口 5683
[2025-08-26 12:00:00] 启动上报：period=2s, net=0, type=CON
[2025-08-26 12:00:00] 已发送 78 字节 (MID=0x0000)
[2025-08-26 12:00:00] 收到响应 code=2.05 (0x45)
[2025-08-26 12:00:00] 发送: temp=25.3, humidity=52.1 -> 状态: 成功 (消息ID: 0x0000)
```

切换 `--net timeout` 且 `--type con` 时，将看到超时与重传的指数退避日志；`--net down` 会直接报告发送丢弃。

### 认证模拟与 COAP 细节

- 设备三元组（内置在 `main.c` → `aliyun_sim_conf_t`）：
  - `product_key = a1b2c3d4`
  - `device_name = dev001`
  - `device_secret = secret123`
- 简化 token 算法（客户端与服务端一致）：
  - `token = HEX32( sum(bytes(productKey+deviceName+deviceSecret)) ^ 0x5A )`
  - 通过 Uri-Query 携带：`token=XXXXXXXX`
- 服务端校验 token：正确返回 `2.05`，否则 `4.01`。
- CoAP 报文字段：
  - 版本 1；类型 `CON`/`NON`；Token 固定 4 字节；MID 自增（0..65535）
  - 选项：`Uri-Host(3)`、`Uri-Path(11)`、`Uri-Query(15)`、`Content-Format(12=50)`
  - 负载：`application/json`，示例：`{"temp":25.3,"humidity":52.1,"abn":0}`

### 传感器模拟

- 正常范围：温度 10–35℃、湿度 30–70%RH
- 约每 20 次出现一次异常值（用于服务端侧健壮性测试）
