#!/bin/bash
set -e

# ========================================
# kiro-rs 一键部署脚本（Ubuntu + Docker）
# ========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- 检查 Docker ---
check_docker() {
    if ! command -v docker &> /dev/null; then
        warn "Docker 未安装，正在安装..."
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER"
        info "Docker 已安装。如果是首次安装，请重新登录 shell 后再运行此脚本。"
        exit 0
    fi

    if ! docker info &> /dev/null 2>&1; then
        error "Docker 未运行或当前用户无权限。请运行: sudo usermod -aG docker \$USER 并重新登录。"
    fi

    info "Docker 已就绪: $(docker --version)"
}

# --- 初始化配置目录 ---
init_config() {
    if [ ! -d "config" ]; then
        mkdir -p config
        info "已创建 config/ 目录"
    fi

    if [ ! -f "config/config.json" ]; then
        cat > config/config.json << 'EOF'
{
  "host": "0.0.0.0",
  "port": 8990,
  "apiKey": "sk-change-me-to-your-api-key",
  "adminApiKey": "sk-change-me-to-your-admin-key",
  "region": "us-east-1",
  "tlsProxyUrl": "http://127.0.0.1:8081"
}
EOF
        warn "已生成 config/config.json 模板，请编辑填入你的 API Key："
        warn "  nano config/config.json"
        NEED_EDIT=true
    else
        info "config/config.json 已存在"
    fi

    if [ ! -f "config/credentials.json" ]; then
        cat > config/credentials.json << 'EOF'
[
  {
    "refreshToken": "your-refresh-token-here",
    "expiresAt": "2025-12-31T00:00:00.000Z",
    "authMethod": "social"
  }
]
EOF
        warn "已生成 config/credentials.json 模板，请编辑填入你的凭据："
        warn "  nano config/credentials.json"
        NEED_EDIT=true
    else
        info "config/credentials.json 已存在"
    fi
}

# --- 构建并启动 ---
build_and_start() {
    if [ "${NEED_EDIT}" = "true" ]; then
        warn ""
        warn "请先编辑配置文件，然后重新运行此脚本或执行:"
        warn "  docker compose up -d --build"
        exit 0
    fi

    info "开始构建 Docker 镜像（首次构建约需 10-20 分钟）..."
    docker compose up -d --build

    info ""
    info "========================================="
    info " kiro-rs 已启动！"
    info " 服务地址: http://$(hostname -I | awk '{print $1}'):8990"
    info " 管理面板: http://$(hostname -I | awk '{print $1}'):8990/admin"
    info "========================================="
    info ""
    info "常用命令:"
    info "  查看日志:   docker logs -f kiro-rs"
    info "  停止服务:   docker compose down"
    info "  重启服务:   docker compose restart"
    info "  更新部署:   git pull && docker compose up -d --build"
}

# --- 主流程 ---
main() {
    info "kiro-rs 部署脚本"
    echo ""

    check_docker
    init_config
    build_and_start
}

main "$@"
