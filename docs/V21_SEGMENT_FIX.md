# v21：修复 iOS 14 加载 UnityFramework 时的段索引错误

日期：2026-10-01。**这是待实机验证的候选版本，不是已确认能启动的版本。**

最终 IPA 大小：1,534,320,055 字节。SHA256：
`2de47f0090b72f88c95469c2024cd2465444272298d43c9f707bce60a8dbba20`。
全部 2,829 个 ZIP 条目的解压/CRC 校验通过；未替换的 2,828 个条目
与 v20 的压缩数据逐字节相同。

## 本次证据

用户的完整日志已归档到
`evidence/ios14-v20-segment-index/phigros-v20-full.log`。
18:48:22 的两次启动（PID 494、495）均出现：

```text
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB segment index 4 too large
```

错误在第 3405、3841、7523、7821 行；失败对象是 UnityFramework。
第 4167、7942 行的 `termination reported by launchd (0, 0, 0)`
与框架加载失败后主程序自行退出相符，可以解释为什么 crashreport 导出为空。
这份日志已经走到主程序调用框架加载的阶段，不能再把 v19 的
`LC_BUILD_VERSION` 错误当成本次故障。

## 已确认的工具链缺陷

`src/chained2dyld.py::_add_segment` 在原有段列表最后追加了
`__DATA_METHLIST`，生成顺序为：

```text
0 __TEXT
1 __DATA_CONST
2 __DATA
3 __LINKEDIT
4 __DATA_METHLIST
```

Apple dyld-832.7.3 的 `dyld3/MachOAnalyzer.cpp` 中，
`invalidRebaseState` 第 1240 行和 `invalidBindState` 第 1816 行都要求
`segmentIndex < linkeditSegIndex`。当前框架的索引 4 因而被拒绝。
原有离线验证器漏掉了这条 dyld3 规则；它先前通过并不能证明可在 iOS 14 加载。

来源：
https://github.com/apple-oss-distributions/dyld/blob/dyld-832.7.3/dyld3/MachOAnalyzer.cpp

本地源码：`reference/dyldsrc/MachOAnalyzer-832.7.3.cpp`。
该版源码对一个重定位操作的诊断名称有复用，因此不能仅凭日志中的
`DO_REBASE_ADD_ADDR_ULEB` 字样判断实际流字节就是该操作码。

## 修复范围

新增 `src/fix_classic_segments.py`，对 v20 框架执行：

1. 段命令调整为 TEXT、DATA_CONST、DATA、DATA_METHLIST、LINKEDIT。
2. 解析操作码及其变长整数、字符串参数后，只把 rebase/bind 中真正的
   SET_SEGMENT 操作码索引 4 改成 3。本次框架共修改两个操作码字节，
   文件偏移分别为 `0x4B0B87D` 和 `0x4B33EE4`。
3. 将无 section 的 LINKEDIT 的 VM 起址从 `0x4DE4000` 调整为
   `0x52B4000`，放在新增数据段之后，同时满足段顺序和内存布局顺序。
   LINKEDIT 的文件位置、大小和内容不因这次 VM 调整而搬动。
4. 保留所有代码、ObjC 数据、section 顺序、符号表、导出表及已有兼容补丁。
   没有重定位指针或符号值指向被移动的原 LINKEDIT VM 范围。
5. 转换器在输出前自动执行同样的规范化，未来构建也会修复这项缺陷。
   验证器增加对应段索引、指针边界、权限与布局检查。

整个 IPA 只替换 UnityFramework。主程序、游戏资源、plist 和其余条目
沿用 v20。这是从 v20 增量生成，当前仍未获得原始完整框架来验证从头重建。

## 验证

- 新验证器能拒绝 v20 框架并复现 `segment index 4 too large`，v21 通过。
- 532,478 个重定位目标与 7,640 个符号绑定逐项按段名、虚拟地址和
  符号/附加值比较一致；除 load commands 和两处段操作码外，所有字节相同。
- 18 项自动化回归测试通过，包含 8 项本次新增测试。
- asio 防护 4 项、包名钩子 5 项、窗口兼容桩 12 项本地模拟检查通过。
- 主程序和框架通过已实现的 iOS 12 与 iOS 13/14 结构规则。
- 校验记录位于 `src/analysis_v21/`；最终 IPA 的完整性、SHA256 和
  所有未替换 ZIP 条目的逐字节比较结果见 `package-verification.json`。

以上均不替代重签后的 iPad 实机启动、渲染、音频和登录验证。

## 重现

在工程根目录执行，输出文件必须尚不存在：

```powershell
New-Item -ItemType Directory -Force src/analysis_v21 | Out-Null
python src/fix_classic_segments.py src/analysis_v20/UnityFramework src/analysis_v21/UnityFramework --report src/analysis_v21/segment-repair.json
python src/verify_segment_repair.py src/analysis_v20/UnityFramework src/analysis_v21/UnityFramework --report src/analysis_v21/semantic-verification.json
python src/verify_ios14.py src/analysis_v20/Phigros src/analysis_v21/UnityFramework
python src/patch_ipa.py Phigros_4.0.0_iOS12_v20.ipa Phigros_4.0.0_iOS12_v21.ipa src/spec/ipaspec_v21.json
python src/analysis_v21/verify_package.py
```

## 实机复测和日志

重新签名并安装根目录 `Phigros_4.0.0_iOS12_v21.ipa`。记录签名/安装工具，
确认选择的是 v21 文件。当前包名和应用内版本号保持不变，避免引入额外改动。
不要求先删除游戏，以免丢失本地数据。

如果仍退出，iPad USB 连接 Mac、解锁并信任电脑后，在 Mac 终端运行：

```bash
idevicesyslog 2>&1 | tee "$HOME/Desktop/phigros-v21-full.log"
```

保持终端运行，在 iPad 打开游戏，退出后等待约 10 秒，然后回终端按
Control+C。发送桌面的整个 `phigros-v21-full.log`，不要筛选关键词。
这个命令采集实时系统日志，不依赖设备已经生成 `.ips`。
若命令立刻返回或报错，保留显示的文字即可。
