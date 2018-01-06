# ELFHooker
基于EFL文件格式Hook的demo，hook了SurfaceFlinger进程的eglSwapBuffers函数，替换为new_eglSwapBuffers。

兼容Android 32位和64位。

注入系列笔记：
[ELF格式分析](https://melonwxd.github.io/2017/11/19/inject-1-elf/)
[so文件加载流程](https://melonwxd.github.io/2017/11/28/inject-2-so/)
[Inject和Hook](https://melonwxd.github.io/2017/12/01/inject-3-hook/)

## 使用
准备:
- 一台root的android设备
- ndk编译环境

分别开2个终端来查看日志:
- adb logcat | grep INJECT
- adb logcat | grep ELFHooker
  如果其他日志太多了可以用 `adb logcat -c`来清理一下日志

然后在新的终端中执行:
- git clone 
- cd jni
- ndk-build
- cd ../libs/arm64-v8a/ (or ../libs/armeabi// if your device is 32-bit)
- adb push .* /data/local/tmp
- adb shell
- su
- cd /data/local/tmp
- chmod 755 inject
- chmod 755 libelfHooker.so 

找到`/system/bin/surfaceflinger`这个进程的pid:
- ps | grep surfaceflinger
- ./inject -p <pid> -l /data/local/tmp/libelfHooker.so
  ![](http://owu391pls.bkt.clouddn.com/cmdlog.png)
  查看日志输出:
  ![](http://owu391pls.bkt.clouddn.com/injectlog.png)
  ![](http://owu391pls.bkt.clouddn.com/hookerlog.png)





## 参考
[Lody's elfHook](https://github.com/asLody/ElfHook)
[ Android中的so注入(inject)和挂钩(hook) - For both x86 and arm](http://blog.csdn.net/jinzhuojun/article/details/9900105)