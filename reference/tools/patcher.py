import os
import sys
import zipfile
import shutil
from pathlib import Path
import keyboard

# ==================== 二进制修补配置 ====================
PATCHES = {
    # 目标 1:  Quit(int exitCode) 
    0x35123D8: b"\xC0\x03\x5F\xD6", # RET
    
    # 目标 2:  Quit()
    0x3512428: b"\xC0\x03\x5F\xD6"  # RET
}
# ================================================================

def get_script_dir():
    """ 获取脚本当前所在的绝对目录位置（完美兼容 .py 与打包后的 .exe） """
    try:
        if getattr(sys, 'frozen', False):
            return Path(sys.executable).resolve().parent
        else:
            return Path(__file__).resolve().parent
    except Exception:
        return Path(sys.argv[0]).resolve().parent

def get_ansi_file_path():
    """ 获取文件路径 """
    try:
        if getattr(sys, 'frozen', False):
            script_path = Path(sys.executable).resolve()
        else:
            script_path = Path(__file__).resolve()
    except Exception:
        script_path = Path(sys.argv[0]).resolve()
    return script_path.with_suffix('.ans')

def show_user_guide():
    """ 读取 .ans 文件并在终端中渲染引导向导 """
    ansi_file = get_ansi_file_path()
    
    if ansi_file.exists():
        try:
            with open(ansi_file, 'r', encoding='cp437', errors='ignore') as f:
                print(f.read())
        except Exception:
            with open(ansi_file, 'r', encoding='utf-8', errors='ignore') as f:
                print(f.read())
    else:
        print("[#] Phigros v3.20 iOS 15 to 12 补丁程序")
        print(f"[!] 提示: 未在同目录下找到色彩资产文件 '{ansi_file.name}'")
        
    print("="*60)
    print("           Phigros v3.20 ios 15 to 12 补丁程序 ")
    print("           作者: πgeon ")
    print("           版本: 1.0.0 ")
    print("           警告：这是一个第三方工具，使用风险自负。")
    print("           警告：打补丁时还需占用另外 4 GB 的空间,\n           请确保设备有足够的剩余空间。")
    print("           注意：此工具与 Pigeon Games 无关联。 ")
    print("           注意：这是一个免费工具,\n           如果你为它付费，你被骗了。")
    print("="*60)
    print("\n[#] 操作准备流程：")
    print("    1. 请先准备好官方正版的两个应用程序组件（IPA 文件）：")
    print("       - Phigros 3.19 旧版安装包（提供 iOS 12 兼容二进制与动态库）")
    print("       - Phigros 3.20 新版安装包（提供全新的曲包资产与地图）")
    print("    2. 将这两个文件进行重新命名对齐：")
    print("       - 将 3.19 的文件更名为: phigrosold.ipa")
    print("       - 将 3.20 的文件更名为: phigrosnew.ipa")
    print("    3. 把这两个更名后的文件，复制到与本程序\"相同的文件夹\"下。")
    print("\n" + "-"*60)
    print("[!] 当一切就绪后，请在键盘上按下： \"Ctrl + G\" 启动自动化修补。")
    print("-"*60 + "\n")

def check_and_prepare_files():
    script_dir = get_script_dir()
    old_ipa = script_dir / "phigrosold.ipa"
    new_ipa = script_dir / "phigrosnew.ipa"
    
    print("[#] 正在验证工作区文件完整性...")
    missing = False
    if not old_ipa.exists():
        print(f"[X] 错误: 找不到 '{old_ipa.name}'")
        missing = True
    if not new_ipa.exists():
        print(f"[X] 错误: 找不到 '{new_ipa.name}'")
        missing = True
        
    if missing:
        print("\n[#] 文件缺失！请确认文件已正确命名并放置在同一个文件夹。")
        print(f"[#] 预期文件夹路径应为: {script_dir}")
        print("[#] 程序正处于监听状态，补齐文件后再次按下 Ctrl+G 。")
        return None, None
        
    print("[+] 验证成功: 已正确锁定基础二进制与资产包。")
    return old_ipa, new_ipa 

def apply_binary_patches(target_framework_path):
    """ 执行二进制替换 - 废除3.20强推的退出逻辑 """
    if not target_framework_path.exists():
        print(f"[-] 错误: 未能在指定路径找到目标文件: '{target_framework_path}'")
        return False

    try:
        file_size = target_framework_path.stat().st_size
        print(f"[*] 目标文件总大小: {file_size} 字节 (约 {file_size / 1024 / 1024:.2f} MB)")
        print("[*] 开始注入补丁...")

        # 使用 r+b 模式覆写特定位置机器码
        with open(target_framework_path, "r+b") as f:
            for offset, patch_bytes in PATCHES.items():
                if offset + len(patch_bytes) > file_size:
                    print(f"[-] 错误: 补丁偏移量 0x{offset:X} 越界！请核对文件版本是否正确。")
                    continue
                
                # 读取原机器码比对
                f.seek(offset)
                original_bytes = f.read(len(patch_bytes))
                
                if original_bytes == patch_bytes:
                    print(f"[!] 提示: 偏移量 0x{offset:X} 处的补丁似乎已经注入过了。")
                    continue
                
                orig_hex = " ".join(f"{b:02X}" for b in original_bytes)
                patch_hex = " ".join(f"{b:02X}" for b in patch_bytes)
                print(f"    -> 正在修改偏移量 0x{offset:X}:")
                print(f"       修改前 (原始机器码): {orig_hex}")
                
                # 指针归位并强行注入 RET 拦截返回
                f.seek(offset)
                f.write(patch_bytes)
                print(f"       修改后 (拦截返回)  : {patch_hex} [成功]")

        print("\n[+] 3.20 原版 UnityFramework 的补丁已注入完成！")
        return True

    except PermissionError:
        print("[-] 错误: 权限不足！请检查该文件是否被其他十六进制编辑器或进程占用。")
        return False
    except Exception as e:
        print(f"[-] 异常崩溃: {str(e)}")
        return False

def core_patching_flow(old_ipa, new_ipa):
    script_dir = get_script_dir()
    old_ws = script_dir / "workspace_old"
    new_ws = script_dir / "workspace_new"
    
    try:
        for ws in [old_ws, new_ws]:
            if ws.exists(): shutil.rmtree(ws)
            os.makedirs(ws, exist_ok=True)

        print("[#] 正在解析 IPA 包体结构...")
        with zipfile.ZipFile(old_ipa, 'r') as z: z.extractall(old_ws)
        with zipfile.ZipFile(new_ipa, 'r') as z: z.extractall(new_ws)

        old_app_dir = next(old_ws.glob("Payload/*.app"), None)
        new_app_dir = next(new_ws.glob("Payload/*.app"), None)
        if not old_app_dir or not new_app_dir:
            old_app_dir = next(old_ws.glob("**/Payload/*.app"), None)
            new_app_dir = next(new_ws.glob("**/Payload/*.app"), None)

        if not old_app_dir or not new_app_dir:
            raise FileNotFoundError("无法正确匹配 IPA 包内的 Payload 结构目录")

        print("\n[#] 1：将 3.19 执行主程序迁移到新版中...")
        old_exec = old_app_dir / "Phigros"
        new_exec = new_app_dir / "Phigros"
        if old_exec.exists():
            shutil.copy2(old_exec, new_exec)
            print("[+] 执行核心主程序互换成功")

        print("\n[#] 2：搬移 3.19 兼容旧系统的 Frameworks 动态库...")
        old_frameworks = old_app_dir / "Frameworks"
        new_frameworks = new_app_dir / "Frameworks"
        if old_frameworks.exists():
            if new_frameworks.exists():
                shutil.rmtree(new_frameworks)
            shutil.copytree(old_frameworks, new_frameworks)
            print("[+] Frameworks 底层依赖库替换成功")

        # === 二进制注入点 ===
        print("\n[#] 框架搬移完成，定位 UnityFramework 执行补丁'...")
        target_framework = new_frameworks / "UnityFramework.framework" / "UnityFramework"
        apply_binary_patches(target_framework)

        print("\n[#] 3：正在替换 3.20 的 global-metadata.dat 文件以修正寻址...")
        old_metadata = old_app_dir / "Data" / "Managed" / "Metadata" / "global-metadata.dat"
        new_metadata = new_app_dir / "Data" / "Managed" / "Metadata" / "global-metadata.dat"
        if old_metadata.exists() and new_metadata.exists():
            shutil.copy2(old_metadata, new_metadata)
            print("[+] global-metadata.dat 覆盖成功")

        print("\n[#] 4：正在迁移旧版 Info.plist 配置文件以解除系统版本限制...")
        old_plist = old_app_dir / "Info.plist"
        new_plist = new_app_dir / "Info.plist"
        if old_plist.exists():
            shutil.copy2(old_plist, new_plist)
            print("[+] Info.plist 配置搬移完成（最低系统要求已降至 iOS 12）")

        print("\n[#] 核心互换完毕！正在重新封装兼容安装包...")
        output_ipa = script_dir / "Phigros_3.20_iOS12_Ready.ipa"
        zip_output = script_dir / "patched_output"
        shutil.make_archive(str(zip_output), 'zip', new_ws)
        if output_ipa.exists():
            output_ipa.unlink()
        os.rename(f"{zip_output}.zip", output_ipa)
        
        print(f"\n[+] 修补成功！已生成：{output_ipa.name}")

    except Exception as e:
        print(f"\n[X] 执行重构互换流程时发生错误: {e}")
    finally:
        if old_ws.exists(): shutil.rmtree(old_ws)
        if new_ws.exists(): shutil.rmtree(new_ws)
        print("[-] 临时缓存工作区清理完毕。")

def on_hotkey_pressed():
    """ 捕获 Ctrl+G 快捷键后的回调控制主程 """
    print("\n[#] 检测到按键 [ Ctrl + G ]，开始修补")
    old_file, new_file = check_and_prepare_files()
    if old_file and new_file:
        core_patching_flow(old_file, new_file)
    print("\n[#] 当前任务结束。你可以保持此窗口开启，或再次按下 Ctrl+G 重新修补。")

if __name__ == "__main__":
    show_user_guide()
    keyboard.add_hotkey('ctrl+g', on_hotkey_pressed)
    keyboard.wait()
