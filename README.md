### 基本思路

1. 将dobby，xdl，keystone，capstone，lief 等库看成插件库，实现他们的lua绑定
2. 通过注入的方式(ptrace / [/proc/mem](https://github.com/erfur/linjector-rs))的方式进行指定pid的注入
3. socket通信实现工具和宿主机的通信[ 这里的宿主机可以是安卓自己或者是windows/linux... ]，当前为了测试方便，不跨平台，就在当前命令行交互
   ( 其实也想使用到更上层好用的gprc/thrift做调用封装，先记录一下想法，先把大体功能跑起来后续再说怎么改把... )
5. 交互目前使用命令行repl命令行补全的方式交互(使用[replxx](https://github.com/AmokHuginnsson/replxx)做命令行补全的交互)，后续可以考虑客户端的实现（python或者是其他语言编写的交互作为前端）
---
### 目标
#### 脱离frida的使用，更加自由的使用 `定制化` `工具化` 的插件库
---
### 当前情况
当前用的是lua绑定，后面也可以考虑使用JavaScript虚拟机，后续可以考虑使用到protobuf之类的协议库方便上层语言的封装调用
1. 两个启动方式 [ 注入 /  仅启动（调试测试用） ]
2. 绑定库
     - keystone（ks）| capstone（cs、dis）
     - BIND_BREAKPOINT （b）
     - linker (somain, wait, disp_soinfo_link, disp_link_map_head, get_soinfo, show_soinfo, show_symtab, find_soinfo)
     - process (getpid, getppid, getgid, geteuid, getuid, getpagesize, getcwd, now)
     - signal (raise, cont)
     - xdl (info, iteratePhdr, addressInfo, xdl_open, xdl_close, xdl_sym, xdl_dsym)
     - others（demangleName、findsyms、syms）
     - ......
3. 功能封装
     - linker wait （断点下在call_constructors，等待so加载，获取基础soinfo信息）
     - ...

### TODO
1. 封装 nativehook 前后端 ( [Dobby](https://github.com/jmpews/Dobby), [frida-gum](https://github.com/frida/frida-gum), [xhook](https://github.com/iqiyi/xHook), [bhook](https://github.com/bytedance/bhook) )
2. 封装 javahook 前后端（ [pine](https://github.com/canyie/pine), [YAHFA](https://github.com/PAGalaxyLab/YAHFA) ） 、 加入测试性功能Java断点 [REF:doc JVMTI](https://docs.oracle.com/javase/8/docs/platform/jvmti/jvmti.html#fieldWatch) | [REF:frida jvmti.js](https://github.com/frida/frida-java-bridge/blob/a3b0de51451dd38e9dfcbaa1fbc744745bab9579/lib/jvmti.js#L37) | [REF:android jvmti.h](https://cs.android.com/android/platform/superproject/main/+/main:art/openjdkjvmti/include/jvmti.h;l=1018)

### 一些其他问题
1. 关于libart部分的代码，虽然clone下来了，但是也只是用作新增代码补全的参考，实际上只用到了头文件，并没有把它们编译进去，这里就涉及到一个问题，如何链接到libart原本的函数，原本的思路是直接pull出手机中的libart.so 然后写一个module让它动态链接的，但是发现安卓高版本是不让我们直接访问系统lib的（但是这个好像有办法解决，暂时没空研究），所以换了个思路直接写一个fakelibart编译进源码, 去把我们后续可能用到的函数全部代理出来，使用xdl解析出来转为函数指针封装其调用，让编译器在静态链接的时候能找到就可以了
2. 关于rpc想使用双向流，但是又考虑到后续可能会进行函数封装给到客户端的js或者lua虚拟机调用，双向流展示倒是方便了，但是不太适合客户端虚拟机
 
##### Lua 绑定使用到 [LuaBridge](https://github.com/vinniefalco/LuaBridge)  / [LuaBridge3](https://github.com/kunitoki/LuaBridge3) 后者更香 [文档](https://kunitoki.github.io/LuaBridge3/Manual)
---
### 备选

##### JavaScript虚拟机有很多备选
0. [hermes](https://github.com/facebook/hermes) Facebook 专门为 React Native 框架在移动端（Android 和 iOS）设计的 JS 引擎
1. [V8](https://chromium.googlesource.com/v8/v8.git)  Google Chrome 浏览器使用的 JS 引擎, 支持最新的 ECMAScript 标准特性
2. [QuickJS](https://github.com/bellard/quickjs) 体积极小启动速度非常快
3. [Duktape](https://github.com/svaarala/duktape) 轻量级支持的 ECMAScript 标准相对较旧（主要支持 ES5/ES6 部分特性）,性能和功能不如 V8、JSC 或 QuickJS擎, 多了一个inline repl
4. [jerryscript](https://github.com/jerryscript-project/jerryscript) ECMAScript 标准支持有限,移动端性能也不太行
5. [mujs](https://github.com/ccxvii/mujs)
6. [ChakraCore](https://github.com/chakra-core/ChakraCore) 来自微软的ERROR: Unsupported target processor: aarch64 (-.-!)
   
##### 总体还是觉得v8比较舒服（除了编译麻烦点），配合dobby hook函数可以使用到lambda，命令行使用起来更简洁

##### UnityHook参考项目
1. [UnityResolve](https://github.com/issuimo/UnityResolve.hpp)  只是简单测试过安卓平台,单文件实现很简洁很香
2. [IL2CPP_Resolver](https://github.com/sneakyevil/IL2CPP_Resolver)  还没测试
3. [BNM-Android](https://github.com/ByNameModding/BNM-Android)

##### Inject的参考代码 (自己把自己注入到unity游戏中)
1. [AndKittyInjector](https://github.com/MJx0/AndKittyInjector) 最完备的实现
2. [AndroidPtraceInject](https://github.com/SsageParuders/AndroidPtraceInject) 注释非常清晰
3. [TinyInjector](https://github.com/shunix/TinyInjector) ...
4. [linjector-rs](https://github.com/erfur/linjector-rs) / [intruducer](https://github.com/vfsfitvnm/intruducer) injection using /proc/mem
5. [NullTrace-Injector](https://github.com/0NullBit0/NullTrace-Injector)

##### JDB CALL IMPL
- 后续也可以绑定进去lua虚拟机，主打一个手动实现jdb在安卓上的调试器功能
- 至于怎么开启jdwp线程参考 [这里 jdwp.ts#L243](https://github.com/axhlzy/Il2CppHookScripts/blob/79ce8ade596dbc591594bd5e361c7228168fb403/Il2cppHook/agent/plugin/jdwp/jdwp.ts#L243)
1. [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier)
2. [jtik](https://github.com/chancerly/jtik)
3. [MemoryMonitor](https://github.com/xingfengwxx/MemoryMonitor)
4. [ART TI](https://source.android.google.cn/docs/core/runtime/art-ti?hl=zh-cn)
5. [jvmti](https://docs.oracle.com/javase/7/docs/platform/jvmti/jvmti.html#SpecificationIntro)
6. [openjdkjvmti events](https://cs.android.com/android/platform/superproject/main/+/main:art/openjdkjvmti/events.h;l=58)
7. [slicer](https://cs.android.com/android/platform/superproject/main/+/main:tools/dexter/slicer/)
8. [jdwp-injector-for-android](https://github.com/wuyr/jdwp-injector-for-android)
9. [HookwormForAndroid](https://github.com/wuyr/HookwormForAndroid)

##### 与Lua虚拟机交互
- 安卓本地端创建一个socket服务器，远端windows/linux使用python或者再编译一个命令行程序用来与安卓通信
1. [websocat](https://github.com/vi/websocat)

---

### 使用说明
使用的话还是很常规的操作

`
push uinjector to /data/local/tmp
`

`
adb shell monkey -p com.xxx.xxx -c android.intent.category.LAUNCHER 1 -> start app
`

`
adb shell pidof com.xxx.xxx -> get pid
`

`
setenforce 0
`

`
./data/local/tmp/uinjector ${pid}
`

然后就是远端操作了，
这里由于还有没客户端代码，所以展示socket的链接测试就用nc, 端口用的是8024

`
    nc 127.0.0.1 8024
`

然后界面没有提示，但是是一个阻塞的socket，可以当作lua shell使用, 参考下图可见已经成功注入了该应用

![xdl:info()](https://github.com/axhlzy/InjectUtils/blob/main/images/inject_nc_test.png)

![asm](https://github.com/axhlzy/InjectUtils/blob/main/images/asm.png)

![linker](https://github.com/axhlzy/InjectUtils/blob/main/images/linker.png)

这里参考代码中xdl的绑定

---

或者是这样考虑，不管用什么方式注入
注入以后调用init函数创建一个socket用来操作后续启动方式 nc去测试，主要就是发送一个最基本的hello信息
然后就是初始化后续的
启动方式
1. 在Android上运行lua引擎，并通过socket传输字符与主机通信
2. 主机运行js引擎，提前约定好rpc常用的方法

---

```

Build说明：

（这些后续有时间可以写个脚本来改改clone下来的这些问题）

1.error: invalid argument '-std=c17' not allowed with 'C++'
改一改 xdl 中的 target_compile_features 和 target_compile_options 为 PRIVATE

2.LIEF中的头文件定义和NDK中有些有冲突，看着爆红的注释掉就是了 （头文件引入的宏定义有点冲突）

3.KittyTrace.hpp 在arm32 build的时候需要把  
#if defined(__arm__)
#define kREG_ARGS_NUM 4
#define sp ARM_sp
#define pc ARM_pc
#define r0 ARM_r0
#define lr ARM_lr
#define cpsr ARM_cpsr
#endif
放在 KittyTrace.cpp 中

4.推荐使用ndk版本 25.1.8937393

```
