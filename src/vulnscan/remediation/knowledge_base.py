"""
Hardening knowledge base for common services.
"""

HARDENING_GUIDES = {
    "ssh": {
        "name": "OpenSSH",
        "recommendations": [
            {
                "title": "禁用密码认证",
                "description": "使用密钥认证替代密码认证，防止暴力破解攻击",
                "action": "编辑 /etc/ssh/sshd_config，设置 PasswordAuthentication no",
                "priority": "high",
            },
            {
                "title": "禁用 root 直接登录",
                "description": "防止攻击者直接获取最高权限",
                "action": "设置 PermitRootLogin no 或 PermitRootLogin prohibit-password",
                "priority": "high",
            },
            {
                "title": "限制 SSH 访问用户",
                "description": "仅允许特定用户通过 SSH 登录",
                "action": "使用 AllowUsers 或 AllowGroups 指令限制登录用户",
                "priority": "medium",
            },
            {
                "title": "更改默认端口",
                "description": "避免自动化扫描器发现 SSH 服务",
                "action": "修改 Port 22 为其他端口（如 2222）",
                "priority": "low",
            },
        ],
    },
    "http": {
        "name": "HTTP Server (Apache/Nginx)",
        "recommendations": [
            {
                "title": "启用 HTTPS",
                "description": "加密传输数据，防止中间人攻击",
                "action": "配置 SSL/TLS 证书，强制 HTTPS 重定向",
                "priority": "critical",
            },
            {
                "title": "添加安全响应头",
                "description": "防止 XSS、点击劫持等攻击",
                "action": "添加 X-Frame-Options, X-Content-Type-Options, CSP 等头部",
                "priority": "high",
            },
            {
                "title": "禁用目录列表",
                "description": "防止敏感文件泄露",
                "action": "Apache: Options -Indexes; Nginx: autoindex off",
                "priority": "medium",
            },
            {
                "title": "隐藏服务器版本",
                "description": "减少攻击者可用信息",
                "action": "Apache: ServerTokens Prod; Nginx: server_tokens off",
                "priority": "low",
            },
        ],
    },
    "mysql": {
        "name": "MySQL/MariaDB",
        "recommendations": [
            {
                "title": "运行安全加固脚本",
                "description": "删除匿名用户、测试数据库，设置 root 密码",
                "action": "执行 mysql_secure_installation",
                "priority": "critical",
            },
            {
                "title": "禁止远程 root 登录",
                "description": "限制 root 仅本地访问",
                "action": "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1')",
                "priority": "high",
            },
            {
                "title": "使用强密码策略",
                "description": "防止弱密码被破解",
                "action": "启用 validate_password 插件",
                "priority": "high",
            },
            {
                "title": "限制网络访问",
                "description": "仅允许必要的 IP 连接",
                "action": "配置 bind-address 和防火墙规则",
                "priority": "medium",
            },
        ],
    },
    "redis": {
        "name": "Redis",
        "recommendations": [
            {
                "title": "设置访问密码",
                "description": "防止未授权访问",
                "action": "在 redis.conf 中设置 requirepass <strong_password>",
                "priority": "critical",
            },
            {
                "title": "禁用危险命令",
                "description": "防止配置被篡改或数据被清除",
                "action": "使用 rename-command 重命名或禁用 FLUSHALL, CONFIG, DEBUG 等命令",
                "priority": "high",
            },
            {
                "title": "绑定本地接口",
                "description": "禁止外网直接访问",
                "action": "设置 bind 127.0.0.1 或仅绑定内网 IP",
                "priority": "high",
            },
            {
                "title": "启用保护模式",
                "description": "拒绝外部无密码连接",
                "action": "设置 protected-mode yes",
                "priority": "medium",
            },
        ],
    },
    "ftp": {
        "name": "FTP Server",
        "recommendations": [
            {
                "title": "使用 SFTP 替代 FTP",
                "description": "FTP 明文传输，存在安全风险",
                "action": "禁用 FTP 服务，改用 SSH 的 SFTP 功能",
                "priority": "critical",
            },
            {
                "title": "禁用匿名登录",
                "description": "防止未授权访问",
                "action": "配置 anonymous_enable=NO",
                "priority": "high",
            },
            {
                "title": "启用 TLS 加密",
                "description": "如必须使用 FTP，至少启用 FTPS",
                "action": "配置 ssl_enable=YES 和证书路径",
                "priority": "high",
            },
        ],
    },
    "smb": {
        "name": "SMB/CIFS",
        "recommendations": [
            {
                "title": "禁用 SMBv1",
                "description": "SMBv1 存在严重漏洞（如 EternalBlue）",
                "action": "设置 min protocol = SMB2",
                "priority": "critical",
            },
            {
                "title": "要求签名",
                "description": "防止中间人攻击",
                "action": "设置 server signing = required",
                "priority": "high",
            },
            {
                "title": "限制共享访问",
                "description": "使用最小权限原则",
                "action": "配置 valid users 和 hosts allow",
                "priority": "medium",
            },
        ],
    },
    "default": {
        "name": "通用服务",
        "recommendations": [
            {
                "title": "保持软件更新",
                "description": "及时安装安全补丁",
                "action": "定期运行系统更新（apt update/yum update）",
                "priority": "critical",
            },
            {
                "title": "配置防火墙",
                "description": "仅开放必要端口",
                "action": "使用 iptables/firewalld/ufw 限制入站流量",
                "priority": "high",
            },
            {
                "title": "启用日志记录",
                "description": "便于安全事件追溯",
                "action": "配置服务日志并定期审查",
                "priority": "medium",
            },
            {
                "title": "实施最小权限",
                "description": "服务以非 root 用户运行",
                "action": "创建专用服务账户，限制文件权限",
                "priority": "medium",
            },
        ],
    },
}

# CVE-specific remediation guidance
CVE_REMEDIATION = {
    "CVE-2021-44228": {
        "title": "Log4j RCE (Log4Shell)",
        "action": "升级 Log4j 至 2.17.0 或更高版本；或设置 log4j2.formatMsgNoLookups=true",
        "reference": "https://logging.apache.org/log4j/2.x/security.html",
    },
    "CVE-2017-0144": {
        "title": "EternalBlue (MS17-010)",
        "action": "安装 MS17-010 安全更新；禁用 SMBv1",
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
    },
    "CVE-2014-0160": {
        "title": "Heartbleed",
        "action": "升级 OpenSSL 至 1.0.1g 或更高版本；重新生成 SSL 证书和密钥",
        "reference": "https://heartbleed.com/",
    },
    "CVE-2019-0708": {
        "title": "BlueKeep",
        "action": "安装 Windows 安全更新；禁用 RDP 或启用 NLA",
        "reference": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708",
    },
}
