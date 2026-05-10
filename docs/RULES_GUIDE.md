# 规则库与主动探测说明

这份文档用于解释：  
“项目里到底有哪些漏洞来源、规则是怎么写的、主动探测和规则库是什么关系。”

## 1. 当前结果来源

项目中的漏洞 / 风险结果主要来自三类来源：

### 1.1 本地规则库匹配

规则文件默认位于：

```text
vuln_assessor/vuln/rules.json
```

匹配依据包括：

- `service`
- `product`
- `port`
- `version_rule`

这类结果通常使用：

- `CVE-*`
- `LAB-*`

作为规则 ID。

### 1.2 主动探测结果

这类结果不依赖你导入的 JSON 规则，而是系统内置的配置弱点检测。

当前包括：

- `CFG-TELNET-OPEN-0001`
- `CFG-FTP-ANON-0001`
- `CFG-REDIS-UNAUTH-0001`
- `CFG-SNMP-DEFAULT-0001`

### 1.3 少量弱口令尝试

这类结果同样属于系统内置主动检测。

当前包括：

- `CFG-SSH-WEAK-PASSWORD-0001`
- `CFG-FTP-WEAK-PASSWORD-0002`
- `CFG-MYSQL-WEAK-PASSWORD-0001`

## 2. 规则库和主动探测的关系

它们的关系可以概括为：

- 规则库负责“基于指纹与版本的推断”
- 主动探测负责“基于协议行为的确认”

最终行为是：

1. 规则库命中生成一批漏洞结果
2. 主动探测命中再生成一批漏洞结果
3. 两批结果合并
4. 一起进入统一风险量化模型

所以，主动探测结果不是单独展示，而是会影响最终报告分数。

## 3. 规则 JSON 结构

一个最小规则示例如下：

```json
[
  {
    "cve_id": "CVE-2021-41773",
    "service": "http",
    "product": "apache httpd",
    "port": 80,
    "version_rule": "2.4.49-2.4.50",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "description": "Apache HTTP Server 路径遍历与潜在远程代码执行漏洞。",
    "remediation": "升级至 2.4.51 及以上。",
    "exploit_maturity": 9.0,
    "asset_criticality": 5.0
  }
]
```

## 4. 字段解释

- `cve_id`
  规则 ID，既可以是 `CVE-*`，也可以是项目内部 `LAB-*`
- `service`
  服务名匹配条件
- `product`
  产品名匹配条件
- `port`
  端口限制；为空表示不限端口
- `version_rule`
  版本规则
- `severity`
  `CRITICAL / HIGH / MEDIUM / LOW`
- `cvss`
  CVSS 基础分
- `description`
  风险描述
- `remediation`
  修复建议
- `exploit_maturity`
  可利用性评分
- `asset_criticality`
  默认资产重要性

## 5. `version_rule` 支持方式

当前常用写法：

- `*`
  任意版本
- `< 2.4.37`
- `<= 7.4`
- `>= 6.0`
- `== 3.0.3`
- `2.4.49-2.4.50`

如果版本缺失，而规则又要求版本比较，系统会主动降低置信度并提示人工确认。

## 6. GUI 与 CLI 里的规则管理

### 6.1 GUI

在 `规则库导入` 页可以：

- 导入本地 JSON
- 选择 `merge`
- 或选择 `replace`

高级功能中还保留：

- 可信 URL 更新

### 6.2 CLI

查看规则摘要：

```powershell
python main.py rules list
```

导入本地规则：

```powershell
python main.py rules import --input docs\rules_feed.example.json --mode merge
```

从 URL 更新：

```powershell
python main.py rules update --url https://example.com/rules.json --mode merge
```

## 7. 写规则时的建议

### 7.1 先小范围、再泛化

优先写：

- 服务名明确
- 产品名明确
- 版本边界清晰

不要一开始就写过宽泛的通配规则。

### 7.2 区分“推断型规则”和“确认型探测”

适合放到 JSON 规则库的：

- 旧版本 Apache
- 旧版本 OpenSSH
- 旧版本 Redis
- SMB / RDP 的版本或端口级规则

适合放到主动探测里的：

- `FTP anonymous`
- `Redis 未授权`
- `SNMP 默认 community`
- 弱口令尝试

### 7.3 优先给出修复建议

即使规则本身很简单，也建议填写：

- 风险是什么
- 为什么危险
- 应该怎么修

这样报告的可读性会明显更好。

## 8. 规则示例文件

你可以直接参考：

- [rules_feed.example.json](./rules_feed.example.json)
- [asset_profile.example.json](./asset_profile.example.json)

## 9. 相关文档

- 项目总览： [PROJECT_GUIDE.md](./PROJECT_GUIDE.md)
- 安全与授权： [SECURITY_ETHICS.md](./SECURITY_ETHICS.md)
- 开发说明： [development/risk_rule_management_guide.md](./development/risk_rule_management_guide.md)
