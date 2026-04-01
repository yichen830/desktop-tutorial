# 中间件 CVE 防御研究手册

这个目录收录了面向防守、排查和加固的中间件漏洞研究资料，不包含利用代码、攻击链编排或面向未授权目标的操作说明。

## 内容概览

- `docs/CVE-2020-1938_Tomcat_Ghostcat_防御分析.md`
- `docs/CVE-2022-26134_Confluence_OGNL_注入_防御分析.md`
- `docs/CVE-2023-50164_Struts2_文件上传路径穿越_防御分析.md`
- `tools/middleware_cve_audit.py`

## 使用场景

- 安全团队做基线核查
- 运维团队做版本盘点
- 应急团队做暴露面初筛
- 内部培训做漏洞成因复盘

## 免责说明

本目录仅用于授权环境下的安全防护、风险排查、版本核验和修复验证。请勿将其用于未授权测试、攻击或破坏活动。

## 快速开始

### 1. 阅读研究文档

优先从 `docs` 目录查看每个漏洞的：

- 影响范围
- 成因拆解
- 暴露面判断
- 排查思路
- 缓解与修复建议

### 2. 运行排查脚本

```bash
python security-research/tools/middleware_cve_audit.py --input security-research/examples/inventory.json
```

脚本根据你提供的资产版本信息，输出：

- 可能命中的高风险版本
- 需要重点关注的服务暴露面
- 建议修复动作

### 3. 资产清单格式

参考 `examples/inventory.json`：

```json
[
  {
    "name": "core-tomcat",
    "product": "tomcat",
    "version": "9.0.30",
    "exposure": ["8080", "8009/ajp"]
  }
]
```

