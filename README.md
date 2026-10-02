# Phigros 4.0.0 iOS 12+ 兼容移植工具链

本项目将原本要求 iOS 15 或更高版本的 Phigros 4.0.0，转换为使用 iOS 12 仍能识别的 Mach-O 加载信息，并处理运行时兼容问题。目标系统范围是 iOS 12 及更高版本；具体设备是否能完整运行，仍取决于设备架构、系统组件、签名方式和游戏运行时行为。

项目参考了 [Han_BuR 的研究成果](https://space.bilibili.com/1575018325)，并结合 Apple 开源的 dyld、objc4 资料以及设备日志进行验证。这里提供的是研究和转换工具，不包含 Phigros 的 IPA、游戏资源或签名证书。

## 主要工作

- 将 arm64 chained fixups 转换为 iOS 12 可处理的 classic dyld rebase/bind 信息。
- 修正 `LC_BUILD_VERSION`、最低系统版本和 SDK 信息。
- 将 iOS 13+ 的相对 Objective-C 方法表转换为 iOS 12 的传统布局。
- 为缺失的系统符号、初始化数组、窗口创建和可用性分支提供兼容处理。
- 修复 iOS 14 dyld 对 `__LINKEDIT` 段索引和段顺序的严格检查。
- 保留签名工具需要的尾部签名空间，并提供 IPA 的增量重打包工具。

## 目录

| 路径 | 作用 |
| --- | --- |
| `src/chained2dyld.py` | Mach-O 转换主程序 |
| `src/port_to_ios12.py` | 从解密 IPA 执行完整转换流程 |
| `src/fix_classic_segments.py` | 修复 classic fixup 的段顺序和段索引 |
| `src/verify_ios14.py` | iOS 12/13/14 加载规则的离线检查 |
| `src/verify_segment_repair.py` | 按虚拟地址和符号语义比较修复前后文件 |
| `src/patch_ipa.py` | 保留其他 ZIP 条目的增量重打包工具 |
| `src/test_*.py` | 转换器回归测试 |
| `portable/PhigrosPortGUI/` | Windows x64 便携 GUI 转换器 |
| `reference/dyldsrc/` | Apple dyld 公开源码的本地参考副本 |
| `docs/STATUS.md` | 当前研究状态和已确认问题 |
| `docs/V21_SEGMENT_FIX.md` | iOS 14 段索引问题的证据与修复说明 |

## 使用

需要 Python 3.10 或更高版本。输入必须是已经解密的、arm64 的 Phigros 4.0.0 IPA；本项目不提供该输入文件。

```powershell
# 在仓库根目录执行
python src/port_to_ios12.py path\to\decrypted-input.ipa output.ipa
```

转换完成后，使用你自己的开发者签名或侧载工具重新签名，再安装到测试设备。签名证书、描述文件和设备标识不会被项目保存或上传。

不想使用命令行时，直接打开 `portable/PhigrosPortGUI/PhigrosPortGUI.exe`，选择输入和输出文件即可。便携版已经包含 Python 运行环境和弱链接清单，不需要另外安装 Python。请从仓库根目录执行上面的命令；如果当前目录已经是 `src`，不要再次写 `src/port_to_ios12.py`。

运行测试：

```powershell
python -m unittest discover -s src -p "test_*.py" -v
```

## 当前状态

当前版本已接近完整可用状态。根据实际设备测试，云功能正常，账号可以登录，歌曲可以正常解锁，触摸操作和音频播放均正常。v20 的完整设备日志曾显示 UnityFramework 因 `segment index 4 too large` 被 dyld 拒绝；v21 已针对该错误调整段顺序并重映射实际 fixup 操作码。后续版本仍可能需要针对特定设备或系统版本进行维护。

## 许可与使用范围

本仓库只发布转换代码、验证代码和研究资料。请自行确认 Phigros、其资源和相关服务的版权及使用条款，不要上传或传播未经授权的 IPA、账号数据、签名材料或设备日志。
