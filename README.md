# dnsay
把 DNS 服务变为一个聊天室

# 使用 && 搭建教程

## Golang

### 本地运行

- 克隆代码 `git clone git@github.com:bob-zebedy/dnsay.git`
- 进入 Golang 目录 `cd dnsay`
- 下载依赖 `go mod download`
- 编译 `make`
- 运行服务端 `./bin/dnsany-server`
- 运行客户端 `./bin/dnsay`

### Docker 部署服务端
- 克隆代码 `git clone git@github.com:bob-zebedy/dnsay.git`
- 进入 Golang 目录 `cd dnsay`
- 编译镜像 `make docker`
- 启动容器 `docker-compose up -d`

# 参数说明

## 服务端

- `--bind` 监听地址; 默认: `0.0.0.0`
- `--port` 监听端口; 默认: `5335`
- `--max-length` TXT 记录最大长度; 默认: `200`
- `--timeout` 会话空闲超时 (秒); 默认: `300`

## 客户端

- `--name` 客户端昵称; 默认: 随机生成
- `--group` 客户端组; 相同的组才能互相收到消息, 默认: `default`
- `--dns` DNS 服务器; 格式: host:port; 默认: `127.0.0.1:5335`
- `--interval` 轮询间隔 (秒); 默认: `0.25`