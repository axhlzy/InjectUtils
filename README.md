### Injector基本思路

1. 将dobby，xdl，keystone，capstone 等库看成插件库，实现他们的lua绑定
2. 通过注入的方式(ptrace / [/proc/mem](https://github.com/erfur/linjector-rs))的方式进行指定pid的注入
3. socket通信实现injector于宿主机的通信
4. 客户端的实现目前考虑使用python作为前端，辅以命令行补全库实现方便的函数调用

#### 目的：脱离frida的使用，更加自由定制化的插件库使用
（后面也可以考虑使用JavaScript虚拟机）

##### Lua 绑定使用到 [LuaBridge](https://github.com/vinniefalco/LuaBridge)  / [LuaBridge3](https://github.com/kunitoki/LuaBridge3) 后者更香 [文档](https://kunitoki.github.io/LuaBridge3/Manual)

##### JavaScript虚拟机有很多备选
1. [V8](https://chromium.googlesource.com/v8/v8.git) 还得是google优选
2. [QuickJS](https://github.com/bellard/quickjs) 经典的极简虚拟机，但是不支持lambda
3. [Duktape](https://github.com/svaarala/duktape) 体验也不错,多了一个inline repl，但是依旧不支持lambda
4. [jerryscript](https://github.com/jerryscript-project/jerryscript) 编译了一个windows版本的好像还挺中规中矩的
5. [ChakraCore](https://github.com/chakra-core/ChakraCore) 来自微软的ERROR: Unsupported target processor: aarch64 (-.-!)
   
##### 总体还是觉得v8比较舒服（除了编译麻烦点），配合dobby hook函数可以使用到lambda，命令行使用起来更简洁

##### UnityHook参考项目
1. [UnityResolve](https://github.com/issuimo/UnityResolve.hpp)  只是简单测试过安卓平台,单文件实现很简洁很香
2. [IL2CPP_Resolver](https://github.com/sneakyevil/IL2CPP_Resolver)  还没测试
3. [BNM-Android](https://github.com/ByNameModding/BNM-Android)

##### Inject的参考代码 (自己把自己注入到unity游戏中)
1. [AndKittyInjector](https://github.com/MJx0/AndKittyInjector) 最完备的实现
2. [AndroidPtraceInject](https://github.com/SsageParuders/AndroidPtraceInject) 注释非常清晰
3. [TinyInjector](https://github.com/shunix/TinyInjector) ...
4. [linjector-rs](https://github.com/erfur/linjector-rs) injection using /proc/mem
5. [NullTrace-Injector](https://github.com/0NullBit0/NullTrace-Injector)

##### JDB CALL IMPL
1. [jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier)

##### 与Lua虚拟机交互
- 安卓本地端创建一个socket服务器，远端windows/linux使用python或者再编译一个命令行程序用来与安卓通信
1. [websocat](https://github.com/vi/websocat)

---

使用的话还是很常规的操作

`
push uinjector to /data/local/tmp
`

`
adbe start com.xxx.xxx -> start app
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

`
Build说明：
1.error: invalid argument '-std=c17' not allowed with 'C++'
改一改 xdl 中的 target_compile_features 和 target_compile_options 为 PRIVATE
2.LIEF中的头文件定义和NDK中有些有冲突，看着爆红的注释掉就是了
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
`