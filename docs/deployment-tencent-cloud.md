# AIOps 部署到腾讯云 2C2G 轻量服务器：方案分析

本文回答三个问题：

1. 这台服务器上，AIOps 到底该不该用 Docker 部署？
2. 如果不熟 Docker，需要先理解哪几件事？（第 2 节是给新手的补课）
3. 具体怎么落地？（含完整命令）

---

## 0. 结论先行

**推荐：AIOps 用 venv + systemd 直接跑在宿主机，不容器化；API 只监听 127.0.0.1，用 SSH 隧道访问 Dashboard。**

理由一句话：AIOps 的核心动作就是**操作宿主机上的 Docker 容器**（代码里有 18 处 `docker` 调用）。容器化它需要一个"能控制宿主机 Docker"的权限，而这个权限一旦给了，容器化带来的隔离收益就被抵消了 —— 反而多了一个 HTTP 入口。

| 方案 | 结论 |
|---|---|
| A. venv + systemd（宿主机） | ✅ **推荐**，权限清晰、最省内存、2C2G 上最现实 |
| B. 容器化 + 挂 docker.sock | ⚠️ 不推荐（等价于把 root 交给一个带 HTTP 入口的进程） |
| C. 容器化 + socket-proxy | 可以，但多一层中间件，单机场景收益不大 |
| D. Kubernetes | 未来形态，2C2G 单机用不上 |

---

## 1. 现状盘点

### 1.1 服务器上已有什么

`shortlink/docker-compose.yml` 起了 4 个容器：

| 容器 | 镜像 | 宿主端口 | 容器内端口 |
|---|---|---|---|
| shortlink-mysql | mysql:8.0 | 13306 | 3306 |
| shortlink-redis | redis:7-alpine（maxmemory 256mb） | 16379 | 6379 |
| shortlink-kafka | apache/kafka:3.9.0 | 19092 | 9092 |
| shortlink-app | Spring Boot（build .） | 8082 | 8080 |

注意：compose 里**没有 Prometheus**，而 AIOps 强依赖它（所有告警规则都走 PromQL 查询）。所以部署 AIOps 前，服务器上必须先有一个 Prometheus 在 9090 端口，且能抓到 `shortlink-app` 的指标。

### 1.2 AIOps 需要什么

```
Prometheus   http://localhost:9090          查指标、跑告警规则
应用         http://localhost:8082          演练时新建一条探测短链
docker CLI   start/stop/restart/inspect/exec/ps   故障演练与自愈
```

其中 docker 相关调用共 18 处：

```
restart ×7   inspect ×3   exec ×2   ps ×2   start ×1   （另加演练的 stop）
```

### 1.3 一个容易被忽略的事实：依赖非常轻

`requirements.txt` 里列了一堆重依赖，但**当前 Python 代码根本没用到**：

| 依赖 | 是否真用到 |
|---|---|
| fastapi / uvicorn / pydantic / pydantic-settings | ✅ 用到 |
| numpy / scikit-learn（IsolationForest） | ✅ 用到（函数内延迟导入） |
| urllib（标准库，查 Prometheus） | ✅ 用到 |
| confluent-kafka / neo4j | ❌ 只在 `KafkaEventBus` / 知识图谱里延迟导入，当前跑的是 `InMemoryEventBus` |
| langchain / langgraph / langchain-openai | ❌ 没用到 |
| prophet / chromadb / pandas | ❌ 没用到 |
| structlog / tenacity | ❌ 没用到 |

**部署时只装前两行就够了**（第 5.2 节）。在 2C2G 上装 `langchain + chromadb + prophet` 不仅费时间，pip 编译阶段就可能把内存吃光。

---

## 2. Docker 补课（这块不熟悉的话先看这里）

### 2.1 镜像 / 容器 / 仓库

- **镜像（image）**：一个只读的模板，里面打包了程序 + 依赖 + 文件系统。类比"类"。
- **容器（container）**：镜像跑起来的实例。类比"对象"。删掉容器，镜像还在。
- **仓库（registry）**：放镜像的地方（Docker Hub）。

```bash
docker images        # 本地有哪些镜像
docker ps            # 正在跑的容器
docker ps -a         # 含已停止的
```

### 2.2 容器有自己独立的网络 —— 这是最大的坑

每个容器默认有**独立的网络命名空间**。这意味着：

> 容器里的 `localhost` 是**容器自己**，不是宿主机。

所以：

- 宿主机上 `curl localhost:8082` 能通（因为 compose 把 8082 映射出来了）
- 但另一个容器里 `curl localhost:8082` **不通**（那是它自己的 8082）

容器内要访问宿主机，用 `host.docker.internal` 这个特殊 DNS 名（Linux 上通常要在 compose 里显式加一行）：

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

这也是 `config/prometheus.yml` 里写 `host.docker.internal:8082` 的原因 —— Prometheus 跑在容器里，要去宿主机的端口抓应用指标。

反过来，**宿主机访问容器**用映射出来的宿主端口（如 16379 → Redis 的 6379）。

### 2.3 端口映射的写法决定"谁能访问"

```bash
-p 8000:8000              # 宿主机所有网卡的 8000 → 容器 8000（公网可达）
-p 127.0.0.1:8000:8000    # 只有宿主机自己能访问（推荐）
```

`-p 8000:8000` + 云安全组放行 = 全世界都能访问你的服务。对 AIOps 这种"能重启容器"的服务尤其危险。

### 2.4 compose 网络：服务名就是主机名

compose 会给这一组容器建一个私有网络，里面**服务名即主机名**。所以 `shortlink-app` 里写的是：

```
jdbc:mysql://mysql:3306/shortlink
spring.data.redis.host=redis
kafka:9092
```

而不是 `localhost:3306`。这是容器之间通信，走的是 compose 内部网络，与宿主端口无关（宿主端口是给外部用的）。

### 2.5 volume：数据活过容器

```yaml
volumes:
  - mysql-data:/var/lib/mysql
```

容器删了、重建了，卷里的数据还在。没有 volume 就等于容器一删数据全没。

### 2.6 docker.sock 是什么 —— 本节重点

Docker 是 C/S 架构：

- `dockerd`（daemon，守护进程）以 **root** 运行在宿主机，真正负责创建/启动/停止容器
- `docker` 命令只是客户端，通过 **`/var/run/docker.sock`** 这个 UNIX socket 跟 daemon 说话

```
你敲 docker ps
   → docker 客户端 → /var/run/docker.sock → dockerd（root）→ 返回结果
```

关键推论：**谁能读写 `/var/run/docker.sock`，谁就等于有了宿主机的 root。**

这个 socket 默认属于 `root:docker`，所以"把用户加入 docker 组"这个常见操作，本质上等于给该用户 root 权限：

```bash
# 加入 docker 组的用户，不需要 sudo 就能做到：
docker run -v /:/host -it alpine chroot /host
# ↑ 把宿主机根目录挂进容器再 chroot，直接拿到宿主机的 root shell
```

同理，如果把一个容器这样启动：

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock ...
```

那这个**容器内的进程**也能执行上面那条命令，从容器里逃逸到宿主机 root。

### 2.7 所以 AIOps 容器化意味着什么

AIOps 的能力恰恰是"自动执行 `docker restart`"：

```
告警 → RCA → 自愈提议 → 审批 → docker restart shortlink-redis
```

如果把它容器化并挂上 docker.sock，就得到：

- 一个**有 root 等价权限**的进程
- 且带一个 **HTTP 入口**（FastAPI，含"故障演练"按钮 = 任意停容器）

两者叠加，等于在服务器上开了一个"HTTP 请求 → 操作任意容器"的口子。这不是理论风险 —— 端口一旦误开到公网就是直接的远程控制入口。

---

## 3. 方案对比

| 维度 | A. venv + systemd | B. 容器化 + 挂 socket | C. 容器化 + socket-proxy |
|---|---|---|---|
| 权限边界 | 一个专用系统用户 | 容器内 = 宿主机 root | proxy 只放行白名单端点 |
| 网络 | 直接用 localhost | 需 host 网络或 host.docker.internal | 同左 |
| 内存开销 | 无额外 | 无额外（但多一层） | 多一个小容器 |
| 部署复杂度 | 低 | 中 | 中高 |
| 适合 2C2G | ✅ | 一般 | 一般 |

**C 方案**如果一定要容器化，用 `tecnativa/docker-socket-proxy` 只暴露需要的端点（`containers/start`、`stop`、`restart`、`inspect`），AIOps 通过它操作，不直接碰 socket。单机项目多维护一个组件，性价比不高。

**D（K8s）**才是这类系统的生产形态：执行动作走 **K8s API**（`rollout restart` / 删 Pod 让控制器重建），权限用 ServiceAccount + RBAC 精确到"哪个 namespace、哪种资源、哪个动词"，审计由 API Server 负责 —— 不需要碰 docker.sock。等哪天迁移到 K8s，这是正确方向。2C2G 单机用不上。

---

## 4. 内存预算（2C2G 是硬约束）

粗估常驻内存：

| 进程 | 估算 |
|---|---|
| MySQL 8.0 | 400–600 MB |
| Kafka（JVM） | 500–800 MB |
| shortlink-app（JVM） | 300–600 MB |
| Redis | ≤256 MB（已配 maxmemory） |
| Prometheus | 200–400 MB |
| **AIOps（Python + sklearn）** | **120–250 MB** |
| 系统 + SSH 等 | 150–250 MB |

总计很容易逼近甚至超过 2 GB。上线前建议：

1. **加 swap**（腾讯云轻量可加 1–2 GB），避免直接 OOM 杀进程
   ```bash
   sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
   sudo mkswap /swapfile && sudo swapon /swapfile
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```
2. **给 JVM 限堆**（shortlink compose 里加环境变量）：
   ```yaml
   environment:
     JAVA_TOOL_OPTIONS: "-Xmx256m -Xms128m"
   ```
   Kafka 同理：`KAFKA_HEAP_OPTS: "-Xmx256m -Xms128m"`
3. **Prometheus 缩短保留期**（默认 15 天很占空间/内存）：
   ```bash
   --storage.tsdb.retention.time=3d
   ```
4. **AIOps 加内存上限**（systemd 里 `MemoryMax=320M`），超了自动重启而不是拖垮整机
5. **演练探测别太猛**：默认 `drill_probe_count=50` 并发 ×25s，在 2C2G 上压力不小，可先调小到 20

---

## 5. 推荐方案落地（A：venv + systemd）

### 5.1 建专用用户

不要用 root 跑。给 AIOps 一个专用用户，并让它能操作 docker：

```bash
sudo useradd -r -m -s /bin/bash aiops
sudo usermod -aG docker aiops      # ⚠️ 等价于给它 root，见 2.6，接受这个前提才做
```

> **更安全的替代**（可选，需要改一行代码）：不给 docker 组，改为 sudo 免密执行**白名单命令**：
> ```
> # /etc/sudoers.d/aiops
> aiops ALL=(root) NOPASSWD: /usr/bin/docker restart shortlink-redis, \
>                            /usr/bin/docker start shortlink-redis, \
>                            /usr/bin/docker inspect shortlink-redis, \
>                            /usr/bin/docker ps
> ```
> 这样即便 AIOps 进程被攻破，也只能重启白名单里的容器，不能任意创建容器。代价是代码里调用 docker 要走 `sudo docker`（或放一个同名包装脚本在 PATH 前面）。

### 5.2 装最小依赖（别装 requirements.txt 全家桶）

```bash
sudo -iu aiops
mkdir -p /opt/aiops && cd /opt/aiops
python3 -m venv venv
./venv/bin/pip install --no-cache-dir \
    fastapi==0.115.12 uvicorn==0.34.2 pydantic==2.11.1 pydantic-settings \
    numpy==2.2.4 scikit-learn==1.6.1
```

`--no-cache-dir` 在磁盘/内存紧张时很有用。scikit-learn 如果编译吃力，可先确认有 wheel（`pip install --only-binary=:all: scikit-learn`）。

### 5.3 部署代码

```bash
# 本地打包上传（排除 .venv/__pycache__）
tar czf aiops.tgz python/
scp aiops.tgz user@server:/tmp
# 服务器上
sudo mkdir -p /opt/aiops && sudo tar xzf /tmp/aiops.tgz -C /opt/aiops --strip-components=1
sudo chown -R aiops:aiops /opt/aiops
```

### 5.4 配置（环境变量前缀是 `AIOPS_`）

`/opt/aiops/.env`：

```bash
AIOPS_PROMETHEUS_URL=http://127.0.0.1:9090
AIOPS_SHORTLINK_BASE_URL=http://127.0.0.1:8082

AIOPS_HEAL_DRY_RUN=true        # 先演练，确认无误再关
AIOPS_DRILL_ENABLED=false      # 演练是唯一能主动停容器的入口，默认关闭
AIOPS_DRILL_PROBE_COUNT=20     # 2C2G 下调小
AIOPS_MONITOR_CHECK_INTERVAL=30
```

对应字段见 `config/settings.py`（`env_prefix = "AIOPS_"`）。

### 5.5 systemd unit

`/etc/systemd/system/aiops.service`：

```ini
[Unit]
Description=Multi-Agent AIOps
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=aiops
Group=aiops
WorkingDirectory=/opt/aiops/python
Environment=PYTHONPATH=/opt/aiops/python
EnvironmentFile=/opt/aiops/.env
ExecStart=/opt/aiops/venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

# 资源约束：2C2G 上必须加
MemoryMax=320M
MemoryHigh=256M

# 安全加固：即便进程被拿下，破坏面也有限
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/aiops

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aiops
sudo systemctl status aiops
journalctl -u aiops -f        # 看日志
```

注意 `--host 127.0.0.1`：只监听本机。**不要在云安全组里放行 8000**。

### 5.6 访问 Dashboard

因为只监听 127.0.0.1，从你电脑上用 SSH 隧道访问：

```bash
ssh -L 8000:127.0.0.1:8000 user@你的服务器IP
# 然后本地浏览器打开 http://127.0.0.1:8000/dashboard
```

这样不需要开任何公网端口，也不需要配 HTTPS/鉴权。

### 5.7 Prometheus 配置（若服务器上还没配）

AIOps 的正确运行前提是 Prometheus 能抓到 `shortlink-app`：

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'shortlink-app'
    metrics_path: '/actuator/prometheus'
    scrape_interval: 15s
    static_configs:
      - targets: ['host.docker.internal:8082']   # Linux 容器里需 extra_hosts 映射
        labels: { service: 'shortlink', env: 'prod' }
```

Prometheus 若跑在容器里，Linux 上必须加：

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

---

## 6. 上线前必须先处理的事

### 6.1 状态全在内存，重启即丢

`incident_history`、`alerts_fired`、统计检测的历史样本 `_history` 都是内存里的 `list`。重启后：

- 历史事件清零、告警数归零
- **统计层要重新攒样本**（IsolationForest 需 ≥20 个点，30 秒一轮 ≈ 至少 10 分钟才有判断力）

对演示环境可以接受；若要当真用，建议落 SQLite/Redis。

### 6.2 演练会真的停容器

「故障演练」按钮 = `docker stop shortlink-redis`，是真故障。如果这台服务器对外提供服务，演练期间跳转会真的失败。只在低峰期做，或者确认它目前只是你的演示环境。

### 6.3 默认值保持保守

```bash
AIOPS_HEAL_DRY_RUN=true     # 自愈只"提议"不执行，确认后再关
AIOPS_DRILL_ENABLED=false   # 需要演练时再开
```

`change_auto_approve_threshold=0.9`：置信度 ≥0.9 才自动放行，低于此走人工审批 —— 保留这个闸门。

### 6.4 审计缺失

现在只有内存里的事件历史，重启即丢，也无法追溯"谁在什么时候触发了自愈"。生产环境至少要落到文件/DB。

---

## 7. 上线验证清单

```bash
# 1) 服务在跑
curl -s http://127.0.0.1:8000/health        # → {"status":"healthy",...}

# 2) 采集循环在转（cycles 会随周期递增）
curl -s http://127.0.0.1:8000/dashboard/state | python3 -m json.tool | head -20

# 3) Prometheus 能查到应用指标
curl -s --data-urlencode 'query=up{job="shortlink-app"}' \
     http://127.0.0.1:9090/api/v1/query

# 4) 内存（装完之后确认没被 OOM）
free -h && systemctl status aiops

# 5) 演练（确认无真实用户影响后）
#    Dashboard 点「故障演练」→ 观察 dependency_hang → 自愈 → Redis 恢复
docker ps --format "{{.Names}} {{.Status}}"
```

---

## 8. 常见坑

| 现象 | 原因 |
|---|---|
| 容器里 Prometheus 抓不到应用 | Linux 需 `extra_hosts: host.docker.internal:host-gateway` |
| AIOps 起来但一直 0 告警 | Prometheus 没抓到 `shortlink-app`，或统计层样本不足（<20） |
| 演练后没告警 | 探测码没拿到（Redis 缓存空 / Redis 已停），见代码 `_resolve_probe_code` 日志 |
| pip 安装时内存爆 | 别装 `requirements.txt` 全家桶；用 `--no-cache-dir`；加 swap |
| 重启后历史事件全没了 | 状态在内存，见 6.1 |
| 服务器变卡 | 2C2G 内存吃紧，见第 4 节（限 JVM 堆 + 加 swap + 缩短 Prometheus 保留期） |
