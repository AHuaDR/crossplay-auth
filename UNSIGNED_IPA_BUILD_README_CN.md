# 无签名 iOS IPA 云构建

此工作流使用 GitHub Actions 的 macOS runner 编译管理员端和用户端，并将未签名 IPA 分别作为 Actions Artifact 保存。它不需要 P12、证书密码或 provisioning profile，也不会读取或上传这些秘密。

## 使用方法
1. 将本压缩包内 `crossplay_auth_v1/` 目录的内容放到 GitHub 仓库根目录（合并，不要再套一层目录）。
2. 确认 `.github/workflows/build-unsigned-ios.yml` 位于仓库根目录的 `.github/workflows/` 下。
3. 在 GitHub 仓库 Actions 页面运行 **Build unsigned iOS IPAs**。
4. 两个 job 均成功后，在该次运行页面底部下载 `crossplay-admin-unsigned-ipa` 和 `crossplay-user-unsigned-ipa`。

## 重要限制
- 这是未签名 IPA。它不能直接安装；请在全能签中尝试重新签名。
- 重新签名时，描述文件必须授权对应 Bundle ID。当前已知描述文件只授权 `app.magenta3492.raspberry1278`，因此它仍不能签这两个 CrossPlay Bundle ID。
- 该工作流在 GitHub macOS runner 上实际运行前，不能宣称 IPA 已经生成。构建失败时请查看对应 job 日志。
- iPhone 实际使用还需要将 App 内 API 地址配置为可访问的 HTTPS 服务地址；当前 `127.0.0.1` 只指向手机自身。
