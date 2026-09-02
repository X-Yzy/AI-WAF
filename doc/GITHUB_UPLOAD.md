# GitHub 上传说明

本项目包含完整训练数据，多个 JSONL 文件超过普通 Git 对象的单文件限制。仓库根目录的
`.gitattributes` 已将 JSONL、ZIP 和部分大型生成数据配置为 Git LFS；当前机器已安装
Git LFS。不要跳过 `git lfs install`，否则推送会失败或把大文件错误地写入 Git 历史。

## 首次创建仓库

```bash
git init
git lfs install
git add .gitattributes
git add .
git lfs ls-files
git status
git commit -m "Initial AI-WAF release"
git branch -M main
git remote add origin <你的 GitHub 仓库地址>
git push -u origin main
```

推送前确认 `git lfs ls-files` 包含 `data/organized/**/*.jsonl`。`runtime/`、离线 ZIP
备份、Python 缓存和本地环境文件已由 `.gitignore` 排除。

## 推荐发布方式

- 源码、配置、测试和 Markdown 文档提交到普通 Git。
- 完整数据通过 Git LFS 提交；不需要公开完整数据时，可在首次 `git add` 前把
  `data/organized/` 加入 `.gitignore`，并改用 Release 或外部数据地址发布。
- `deployment/server_runtime.zip` 是生成的服务器包，建议作为 GitHub Release 附件，
  不要长期提交多个版本到仓库历史。
- 推送前运行 `python -m pytest -q` 和 `python tools/verify_delivery.py`。
