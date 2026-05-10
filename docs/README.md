# 文档中心

本目录已经按“主文档优先、草稿归档”的方式重新整理。

如果你是第一次接触本项目，建议按下面顺序阅读：

1. [INSTALL.md](./INSTALL.md)：安装、依赖、自检
2. [usage_guide.md](./usage_guide.md)：推荐操作流程
3. [USER_MANUAL.md](./USER_MANUAL.md)：按 GUI 页签理解功能
4. [PROJECT_GUIDE.md](./PROJECT_GUIDE.md)：系统设计、模块边界、风险模型

如果你要做答辩或实验复现，继续看：

1. [demo_lab_guide.md](./demo_lab_guide.md)：本地靶场与演示路径
2. [test_report.md](./test_report.md)：当前测试结论与留档
3. [defense_script_10min.md](./defense_script_10min.md)：10 分钟答辩讲稿
4. [external_validation_manual.md](./external_validation_manual.md)：外网授权验证手册

如果你要维护规则或补充安全说明，继续看：

1. [RULES_GUIDE.md](./RULES_GUIDE.md)：规则库、主动探测、导入更新
2. [SECURITY_ETHICS.md](./SECURITY_ETHICS.md)：授权、范围、合规边界
3. [FAQ.md](./FAQ.md)：常见问题排障

## 当前结构

- `INSTALL.md`
  Windows 主路径安装文档。
- `usage_guide.md`
  面向实际操作的 GUI/CLI 流程手册。
- `USER_MANUAL.md`
  面向第一次上手的用户说明。
- `PROJECT_GUIDE.md`
  面向论文、答辩和项目讲解的总览文档。
- `demo_lab_guide.md`
  本机回环靶场使用说明。
- `external_validation_manual.md`
  面向“自有公网测试机”的验证手册。
- `RULES_GUIDE.md`
  规则库与主动探测说明。
- `SECURITY_ETHICS.md`
  合规、授权、范围控制。
- `test_report.md`
  项目测试结论与留档位置。
- `defense_script_10min.md`
  答辩讲稿与演示顺序。
- `asset_profile.example.json`
  资产画像示例。
- `rules_feed.example.json`
  规则导入示例。

## 子目录

- [`thesis/`](./thesis/README.md)
  论文模板、章节草稿、实施计划。
- [`development/`](./development/README.md)
  代码讲解与设计说明。
- `superpowers/`
  代理工作流内部留档，不作为用户文档入口。

## 使用建议

- 想跑通系统：先看 `INSTALL.md` 和 `usage_guide.md`
- 想理解项目：看 `PROJECT_GUIDE.md`
- 想准备答辩：看 `demo_lab_guide.md`、`test_report.md`、`defense_script_10min.md`
- 想做真实网络验证：先看 `SECURITY_ETHICS.md`，再看 `external_validation_manual.md`
