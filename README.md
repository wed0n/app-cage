一个用于阻止 AI 执行未经授权操作的工具。
## 用法
1. 使用前需要[关闭 SIP](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection)，或者使用具有 [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) 权限的证书签名。
2. 在你的 AI IDE 的 Terminal 中执行以下命令，执行命令时当前工作目录将自动加入允许修改的路径列表中。
    ```bash
    sudo app-cage
    ```
## 配置
配置文件路径`~/.app-cage.toml`
### 配置示例
```toml
enforcing = true # 强制模式开启后将阻止操作，关闭则输出警告
whitelist = [
    "~/.local/state/+",
    "~/.local/share/fish/+",
    "~/.local/share/z/:",
    "~/.gemini/+",
    "~/.antigravity/+",
    "~/Library/Application Support/Antigravity/+",
    "~/Library/Caches/com.google.antigravity/+",
    "~/Library/Caches/com.google.antigravity.ShipIt/+",
    "~/Library/HTTPStorages/com.google.antigravity/+",
    "/Applications/Antigravity.app/+",
] #允许修改的路径列表，语法参考 https://github.com/viz-rs/path-tree

[gh]
enable = true

[gh.auth]
view = true
update = false

[gh.repo]
view = true
create = false
content = false #是否可执行影响内容的命令
maintain = false #是否可执行影响生命周期的命令

[gh.issue]
view = true
create = false
content = false
maintain = false

[gh.pr]
view = true
create = true
content = false
maintain = false
```
## 编译
```bash
cargo build --release
codesign -s - -f --entitlements codesign.plist target/release/app-cage
```