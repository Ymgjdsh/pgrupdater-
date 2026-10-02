# Phigros 4.0.0 / 4.0.1 iOS 12+ 兼容移植工具链

**目前支持 Phigros 4.0.0 和 4.0.1 的转换。**

本项目将原本要求 iOS 15 或更高版本的 Phigros 4.0.0 / 4.0.1，转换为使用 iOS 12 仍能识别的 Mach-O 加载信息，并处理运行时兼容问题。目标系统范围是 iOS 12 及更高版本；Swift 运行库要求 iOS 12.2 或更高版本，iOS 12.0/12.1 暂不保证。具体设备是否能完整运行，仍取决于设备架构、系统组件、签名方式和游戏运行时行为。

4.0.0 已有用户真机验证；4.0.1 当前为候选支持，已完成补丁地址适配与离线验证，仍待真机反馈。

项目参考了 [Han_BuR 的研究成果](https://space.bilibili.com/1575018325)，并结合 Apple 开源的 dyld、objc4 资料以及设备日志进行验证。这里提供的是研究和转换工具，不包含 Phigros 的 IPA、游戏资源或签名证书。

<img width="895" height="615" alt="image" src="https://github.com/user-attachments/assets/e8cfe972-d360-44c7-b81a-4052c87c3783" />


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
| `src/runtime_profiles.py` | 按 UnityFramework UUID 选择 4.0.0 / 4.0.1 补丁位置 |
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

需要 Python 3.10 或更高版本。输入必须是已经解密的、arm64 的 Phigros 4.0.0 / 4.0.1 IPA（破壳 IPA）；本项目不提供该输入文件。工具只对已识别的 UnityFramework 构建应用固定地址补丁，未知构建会停止。

```powershell
# 在仓库根目录执行
python src/port_to_ios12.py path\to\decrypted-input.ipa output.ipa
```

也可以从任意目录调用仓库根目录的 `port_to_ios12.cmd`，它会自动使用正确的脚本路径：

```powershell
path\to\pgrupdater-\port_to_ios12.cmd path\to\decrypted-input.ipa path\to\output.ipa
```

转换完成后，使用你自己的开发者签名或侧载工具重新签名，再安装到测试设备。签名证书、描述文件和设备标识不会被项目保存或上传。

不想使用命令行时，直接打开 `portable/PhigrosPortGUI/PhigrosPortGUI.exe`，选择输入和输出文件即可。便携版已经包含 Python 运行环境和弱链接清单，不需要另外安装 Python。如果当前目录已经是 `src`，不要再次写 `src/port_to_ios12.py`。

请保留整个便携文件夹，包括 `PhigrosPortWorker.exe` 和 `_internal`。
转换在隐藏的工作进程中运行，日志会实时显示；只有检查输出 IPA 完整后才提示完成。
App Store 原始加密 IPA（`cryptid=1`）会在开始时被明确拒绝，本工具不提供解密功能。

运行测试：

```powershell
python -m unittest discover -s src -p "test_*.py" -v
```

重新构建 Windows 便携版（在独立环境中安装打包依赖）：

```powershell
python -m venv portable_build/venv
portable_build/venv/Scripts/python.exe -m pip install pyinstaller==6.22.3
portable_build/venv/Scripts/python.exe src/build_portable.py
```

构建前关闭转换器。生成结果位于 `portable/PhigrosPortGUI/`，分发时保留整个文件夹。

## 当前状态

2026-10-02：加入 Phigros 4.0.1（build 6）候选支持，重新定位退出函数、崩溃回调、系统版本判断和账号登录相关修补点，并检查补丁前的指令与字符串。修复压缩游戏资源中的偶然字节被错误识别为 ZIP64 标记、导致重打包失败的问题。4.0.1 的离线检查通过不等于设备已确认可运行；请重新签名后真机测试启动、音频、触摸和云存档。

4.0.0 已接近完整可用状态。根据用户实际设备测试，云功能正常，账号可以登录，歌曲可以正常解锁，触摸操作和音频播放均正常。v20 的完整设备日志曾显示 UnityFramework 因 `segment index 4 too large` 被 dyld 拒绝；v21 已针对该错误调整段顺序并重映射实际 fixup 操作码。后续版本仍可能需要针对特定设备或系统版本进行维护。

## 许可与使用范围

本仓库只发布转换代码、验证代码和研究资料。请自行确认 Phigros、其资源和相关服务的版权及使用条款，不要上传或传播未经授权的 IPA、账号数据、签名材料或设备日志。
