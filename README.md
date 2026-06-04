# AI 生产力插件集

这个仓库是 Sheldon 维护的本地 Codex 插件市场。入口文件是：

- `.agents/plugins/marketplace.json`

当前已接入插件：

- `imap-smtp-mail`：Sheldon 开发和维护的 IMAP/SMTP 邮箱插件，支持 QQ 邮箱、网易 163/126/yeah、腾讯企业邮箱、阿里企业邮箱、139 邮箱和自定义 IMAP/SMTP 邮箱。
- `lark-cli`：Sheldon 打包和维护的飞书 / Lark CLI 插件，复用现有飞书 `lark-*` skills，通过本机 `lark-cli` 操作文档、知识库、日程、消息、多维表格等。

## 在 Codex 中使用

在 Codex App 中打开这个仓库后，插件市场会读取 `.agents/plugins/marketplace.json`，并展示 `AI 生产力插件集` 下的 `IMAP/SMTP 邮箱` 和 `飞书 / Lark CLI` 插件。

安装 IMAP/SMTP 邮箱插件后，推荐直接让 Codex 打开本地配置向导：

```text
打开邮箱配置向导
```

向导会在本机浏览器打开，用户选择邮箱服务商，填写邮箱地址和授权码，然后点保存即可，不需要手动改 JSON。

也可以手动配置：

```bash
mkdir -p ~/.imap-smtp-mail
cp ./plugins/imap-smtp-mail/config/accounts.example.json ~/.imap-smtp-mail/accounts.json
```

编辑 `~/.imap-smtp-mail/accounts.json`，填入邮箱地址、账号名和客户端授权码。

不要使用网页登录密码；QQ、网易等邮箱通常需要先在网页端设置里开启 IMAP/SMTP，并生成授权码或客户端专用密码。

安装飞书 / Lark CLI 插件后，可以直接使用现有飞书 skill 的表达方式，例如：

```text
读取飞书文档并总结
查询我的飞书日程
```

该插件不新增独立 MCP wrapper，也不重新封装 OpenAPI；它打包现有 `lark-*` skill，并沿用本机已安装和已登录的 `lark-cli`。

## 从 GitHub 安装

把这个仓库发布到 GitHub 后，其他用户在 Codex App 中打开或克隆该仓库即可看到这个本地插件市场。
如果要进入官方公共插件市场，还需要按官方发布流程提交审核；本仓库已经具备本地 marketplace 结构。

本仓库只提交插件源码、skill 和示例配置，不包含任何真实邮箱账号、授权码、飞书 token 或本机缓存。真实邮箱账号配置会保存在使用者自己的 `~/.imap-smtp-mail/accounts.json`。
