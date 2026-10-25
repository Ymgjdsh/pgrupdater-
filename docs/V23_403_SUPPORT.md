# Phigros 4.0.3 候选适配（v23）

日期：2026-10-25。输入是用户提供的已解密 arm64 IPA，应用声明版本 4.0.3、build 0；主程序及 UnityFramework 的 cryptid 均为 0。UnityFramework UUID 为 70f666eb-6f4e-325e-9e8a-75b568085f26。应用 Info.plist 虽将最低版本写成 10.0，两个 Mach-O 实际仍以 iOS 15 为最低版本，框架 Info.plist 仍写 15.0。

## 新版补丁位置

旧版固定地址不能沿用。新配置按 UnityFramework UUID 选取，并继续检查入口指令、字符串、selector 和未占用代码空间；IPA 声称的版本若与二进制配置不一致会提前拒绝。

| 目标 | 4.0.3 地址 |
| --- | --- |
| Application.Quit(int) / Application.Quit() | 0x39237A0 / 0x39237F0 |
| 崩溃回调 | 0x8A1D48 |
| 系统版本判断入口 | 0x1443D08 |
| bundle_id CFString / 原字符串 | 0x47E6FE8 / 0x43A3874 |
| bundleIdentifier stub / selector 引用 | 0x3C31620 / 0x480FDB8 |
| 兼容代码起始空隙 | 0x4490440 |

退出函数通过其 UnityEngine.Application::Quit(System.Int32) 字符串引用确认；崩溃回调通过注册者传入的函数地址确认；系统版本函数包含对 __availability_version_check 的调用。登录补丁检查 CFString 的 flags、长度、字符串指针及 Objective-C selector/stub 引用。

## 离线结果

- 完整转换生成候选 IPA，输出 2,311,425,864 字节；ZIP 条目从 2,950 变为 2,940，去除旧签名相关条目。
- 转换后两个 Mach-O 通过现有 iOS 12 classic dyld 与 iOS 13/14 加载规则检查，且不保留 chained fixups。
- 输出 IPA 全部条目的 CRC 检查通过；应用版本保留 4.0.3，最低系统版本改为 12.0。
- 34 项回归测试通过；重新构建的 Windows 便携后台程序完整转换了同一输入，所得 IPA 与源码运行结果的 SHA-256 完全一致。
- 上述结果不等同于真机启动、账号、云功能、音频和触摸验证。仍需重新签名后测试，尤其是低内存 iOS 12 设备。

IPA、证书和设备日志不随源码发布。iOS 12.0/12.1 的 Swift 运行库兼容性仍不保证；请使用 iOS 12.2 或更新版本测试。
