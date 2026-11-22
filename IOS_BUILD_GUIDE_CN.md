# CrossPlay Auth 双 iOS IPA 构建说明

## 当前状态
- 两个 Expo App 源码已包含在工程中，Bundle ID 分别为 `com.crossplay.auth.admin` 和 `com.crossplay.auth.user`。
- 服务端自动化测试：8/8 通过。
- 本工程尚未完成原生 iOS 云构建、设备安装验证或签名；当前交付不是 IPA。

## 云构建条件
1. 一个 Expo 账号（用于 EAS Build）。
2. Apple Developer 签名材料。Ad Hoc 安装需要与目标设备 UDID 匹配的 provisioning profile；P12 单独不足以签出可安装的 Ad Hoc IPA。
3. 每个 App 的 EAS Build 需要分别运行一次。不要把 P12、证书密码或 provisioning profile 提交到 Git 仓库。

## 构建步骤
在有网络的电脑或 CI 环境安装 Node.js 和 EAS CLI：

```bash
npm install -g eas-cli
eas login
./build-ios.sh
```

首次构建时，EAS 会要求配置 Apple 签名凭据。按其提示选择与安装方式匹配的 Ad Hoc/内部测试签名，并为目标 iPhone 注册 UDID。构建成功后，从 EAS 提供的构建页面分别下载两个 `.ipa`。

## 服务端地址
App 登录页允许填写 API 地址。部署服务端后，填写可从 iPhone 访问的 HTTPS 地址。不要填写 `127.0.0.1`，它指向手机本机而不是云服务器。

## 重要限制
- 仅有 P12 和密码不保证能够生成可安装 IPA；还需要匹配的描述文件和设备授权（Ad Hoc 场景）。
- EAS 云构建需要 Expo 账号授权；当前运行环境没有 Expo/EAS 登录会话或访问令牌，不能代替用户登录或触碰其 Apple 证书。
- 构建成功不等于生产可用。服务端仍需部署到 HTTPS，媒体源需按授权合法接入，并完成真机播放和撤销测试。
