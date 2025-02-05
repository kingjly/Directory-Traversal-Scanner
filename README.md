# Directory Traversal Scanner 🔍

[English](README_EN.md) | [中文](README.md)

## 📖 项目描述

Directory Traversal Scanner 是一个高性能的目录遍历漏洞扫描工具，专门用于检测和验证 Web 应用程序中的路径遍历漏洞。通过异步并发扫描和智能 WAF 绕过技术，帮助安全研究人员快速发现潜在的安全隐患。

## ✨ 特点

- 🚄 异步并发扫描，支持大规模目标检测
- 🛡️ 内置 WAF 绕过技术
- 🎯 智能参数识别和目标提取
- 📊 实时扫描进度展示
- 📝 自动生成详细扫描报告
- 🔄 支持自定义 payload
- 🌈 美观的命令行界面

## 🛠️ 技术栈

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![aiohttp](https://img.shields.io/badge/aiohttp-latest-green)
![rich](https://img.shields.io/badge/rich-latest-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

- Python 3.8+
- aiohttp (异步 HTTP 客户端/服务器)
- rich (终端美化)
- urllib.parse (URL 解析)

## 🚀 快速开始

### 先决条件

- Python 3.8 或更高版本
- pip 包管理器

### 📦 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/directory-traversal-scanner.git

# 进入项目目录
cd directory-traversal-scanner

# 安装依赖
pip install -r requirements.txt
```

### 🎮 基本使用

```bash
# 扫描单个 URL
python scanner.py -u "http://example.com/page.php?file=test.txt"

# 扫描多个 URL，启用 WAF 绕过
python scanner.py -u "http://example1.com" "http://example2.com" --waf

# 自定义并发数和超时时间
python scanner.py -u "http://example.com" -c 200 -t 10
```

## 📋 命令行参数

```
-u, --urls        目标 URL（必需，支持多个）
-d, --depth       最大遍历深度（默认：4）
--waf            启用 WAF 绕过技术
-c, --concurrency 最大并发请求数（默认：20）
-t, --timeout     请求超时时间（默认：5秒）
-o, --output      输出报告文件名（默认：scan_report.json）
```

## 📊 扫描报告

扫描完成后会在 `results` 目录下生成详细的扫描报告，包含：
- 扫描配置信息
- 目标 URL 列表
- 扫描统计数据
- 发现的漏洞详情
- 完整的扫描命令

## 🤝 如何贡献

欢迎提交 Pull Request 来改进这个项目！

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的修改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## ⚠️ 免责声明

本工具仅用于授权的安全测试和研究目的。使用本工具进行未经授权的测试可能违反相关法律法规，使用者需自行承担所有风险和法律责任。

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🌟 鸣谢

- 感谢所有贡献者
- 感谢开源社区的支持

---

💡 **小贴士**：如果这个项目对您有帮助，请给个 Star 支持一下！
