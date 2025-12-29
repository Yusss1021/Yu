#!/bin/bash
# VulnScanner 多主机演示环境启动脚本

set -e
cd "$(dirname "$0")"

echo "╔══════════════════════════════════════════════╗"
echo "║   VulnScanner 多主机演示环境                 ║"
echo "╚══════════════════════════════════════════════╝"

case "${1:-start}" in
    start)
        echo "[1/2] 启动容器..."
        docker-compose up -d

        echo "[2/2] 等待服务就绪..."
        sleep 5

        echo ""
        echo "✓ 环境已就绪！"
        echo ""
        echo "┌─────────────────────────────────────────────────┐"
        echo "│  主机列表 (172.28.0.2 ~ 172.28.0.8)             │"
        echo "├─────────────────────────────────────────────────┤"
        echo "│  172.28.0.2   DVWA (Web漏洞)      :8080         │"
        echo "│  172.28.0.3   WebGoat (OWASP)     :8081         │"
        echo "│  172.28.0.4   Juice Shop          :3000         │"
        echo "│  172.28.0.5   MySQL (弱密码)      :3306         │"
        echo "│  172.28.0.6   Redis (未授权)      :6379         │"
        echo "│  172.28.0.7   SSH (弱密码)        :2222         │"
        echo "│  172.28.0.8   FTP (弱密码)        :21           │"
        echo "└─────────────────────────────────────────────────┘"
        echo ""
        echo "扫描命令:"
        echo "  sudo venv/bin/python -m cli.main scan 172.28.0.2-8 --verify"
        echo ""
        echo "Web界面目标: 172.28.0.2-8"
        ;;

    stop)
        echo "停止容器..."
        docker-compose down
        echo "✓ 已停止"
        ;;

    status)
        docker-compose ps
        ;;

    *)
        echo "用法: $0 {start|stop|status}"
        exit 1
        ;;
esac
