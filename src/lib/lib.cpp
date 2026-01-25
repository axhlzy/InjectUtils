#include "KittyMemoryEx.hpp"
#include "main.h"
#include "config.h"

// 使用配置常量替代硬编码
const char *PIPE_NAME = Config::PIPE_NAME;

void serializeToPipe(int pipe_fd, const std::vector<std::string> &data) {}

void deserializeFromPipe(int pipe_fd, std::vector<std::string> &data) {}

#include <LuaSocket/LuaReplClient.hpp>
#include <LuaSocket/LuaReplServer.hpp>

extern int installRepl(const std::vector<std::string> &suggestions,
                       std::function<void(const std::string &)> callback);

std::vector<std::string> getLuaCommands(lua_State *L = G_LUA) {
  std::vector<std::string> functionNames;
  lua_pushglobaltable(L);
  lua_pushnil(L);
  while (lua_next(L, -2) != 0) {
    if (lua_isfunction(L, -1)) {
      const char *name = lua_tostring(L, -2);
      functionNames.push_back(name);
    } else if (lua_istable(L, -2) != 0) {
      // ...
    }
    lua_pop(L, 1);
  }
  lua_pop(L, 1);
  return functionNames;
}

// run on remote (在目标应用进程中运行)
void repl_socket(lua_State *L) {
  logd("[*] start lua repl | Socket Mode | Port: %d", SOCKET_PORT);
  console->info("[*] Starting Lua REPL Server on port {}", SOCKET_PORT);
  
  try {
    boost::asio::io_context io_context;
    LuaReplServer server(io_context, SOCKET_PORT, L);
    
    console->info("[*] Server started successfully, waiting for connections...");
    logd("[*] Server started successfully on port %d", SOCKET_PORT);
    
    io_context.run();
  } catch (const boost::system::system_error &e) {
    std::string error_msg = fmt::format("[!] Socket error: {} (code: {})", 
                                        e.what(), e.code().value());
    console->error("{}", error_msg);
    loge("%s", error_msg.c_str());
    
    // 检查常见错误
    if (e.code().value() == 98) { // EADDRINUSE
      console->error("[!] Port {} is already in use", SOCKET_PORT);
      loge("[!] Port %d is already in use. Try: netstat -tuln | grep %d", 
           SOCKET_PORT, SOCKET_PORT);
    } else if (e.code().value() == 13) { // EACCES
      console->error("[!] Permission denied. Need root?");
      loge("[!] Permission denied to bind port %d", SOCKET_PORT);
    }
  } catch (const std::exception &e) {
    std::string error_msg = fmt::format("[!] Server error: {}", e.what());
    console->error("{}", error_msg);
    loge("%s", error_msg.c_str());
  }
}

void start_local_repl() {
  console->info("[*] Starting local REPL client, connecting to port {}", SOCKET_PORT);
  logd("[*] Connecting to localhost:%d", SOCKET_PORT);
  
  LuaReplClient client(std::to_string(SOCKET_PORT));
  
  // 使用改进的连接方法，支持重试和超时
  if (!client.connect(30, 1000)) {  // 30次重试，每次间隔1秒
    console->error("[!] Failed to connect to server");
    return;
  }
  
  console->info("[*] Connected! Type Lua commands or 'exit' to quit");

  installRepl({""}, [&](const std::string &input) {
    if (input == "exit" || input == "q") {
      console->info("[*] Closing connection...");
      client.disconnect();
    } else if (!input.empty()) {
      client.send_message(input);
    }
  });
}

void repl(lua_State *L) {
  logd("[*] start lua repl | Debug Mode");
  installRepl(getLuaCommands(L), [&](const std::string &input) {
    if (input == "exit" || input == "q")
      exit(0);
    if (input.empty())
      return;
    int status = luaL_dostring(L, input.c_str());
    if (reinterpret_cast<LUA_STATUS &>(status) != LUA_STATUS::LUA_OK_) {
      const char *msg = lua_tostring(L, -1);
      lua_writestringerror("%s\n", msg);
      lua_pop(L, 1);
    }
  });
}

auto getApp(JNIEnv *env) -> jobject {
  if (env == nullptr) {
    console->error("getApp: env is nullptr");
    return nullptr;
  }
  
  jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
  if (activityThreadClass == nullptr) {
    return nullptr;
  }
  jmethodID currentApplicationMethod = env->GetStaticMethodID(
      activityThreadClass, "currentApplication", "()Landroid/app/Application;");
  if (currentApplicationMethod == nullptr) {
    return nullptr;
  }
  jobject application = env->CallStaticObjectMethod(activityThreadClass,
                                                    currentApplicationMethod);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    return nullptr;
  }
  return application;
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {

  S_TYPE = vm == nullptr ? START_TYPE::DEBUG : START_TYPE::SOCKET;

  std::string msg = fmt::format("[+] CURRENT -> {} | {} | {}", (int)getpid(),
                                KittyMemoryEx::getProcessName(getpid()),
                                magic_enum::enum_name(S_TYPE));
  logd("%s", msg.c_str());
  std::cout << msg << std::endl;

  g_thread = std::make_unique<std::thread>([=]() {
    if (vm != nullptr) {
      g_jvm = vm;

      logd("------------------- JNI_OnLoad -------------------");
      if (vm->AttachCurrentThread(&g_env, nullptr) == JNI_OK) {
        logd("[*] AttachCurrentThread OK");
      };
      if (vm->GetEnv((void **)&g_env, JNI_VERSION_1_6) == JNI_OK) {
        logd("[*] GetEnv OK | env:%p | vm:%p", g_env, vm);
      }
      g_application = getApp(g_env);
    }
    pthread_setname_np(pthread_self(), EXEC_NAME);
    startLuaVM();
    if (vm != nullptr) {
      vm->DetachCurrentThread();
    }
  });

  if (S_TYPE == START_TYPE::DEBUG && g_thread->joinable()) {
    g_thread->join();
  }

  return JNI_VERSION_1_6;
}

// noreturn
inline void startRepl(lua_State *L) {
  if (S_TYPE == START_TYPE::DEBUG) {
    repl(L);
  } else if (S_TYPE == START_TYPE::SOCKET) {
    repl_socket(L);
  }
}

static int countRestartTimes = 0;

void initVM() {
  if (++countRestartTimes > Config::MAX_RESTART_TIMES)
    raise(SIGKILL);

  lua_State *L = luaL_newstate();

  G_LUA = std::ref(L);

  luaL_openlibs(L);

  bind_libs(L);

  startRepl(L);

  // test(L);

  lua_close(L);
}

void startLuaVM() {

  reg_crash_handler();

  initVM();
}

#ifdef GENLIB

__MAIN__ void preInitInject() {

  void *handle = xdl_open(Config::LIBART_SO, XDL_DEFAULT);
  if (handle == nullptr) {
    logd("[!] xdl_open %s failed", Config::LIBART_SO);
    return;
  }
  void *addr = xdl_sym(handle, "JNI_GetCreatedJavaVMs", nullptr);
  if (addr == nullptr) {
    logd("[!] xdl_sym JNI_GetCreatedJavaVMs failed");
    return;
  }

  // logd("[*] %d JNI_GetCreatedJavaVMs -> %p", getpid(), addr);

  xdl_close(handle);

  using JNI_GetCreatedJavaVMs_t =
      jint (*)(JavaVM **vmBuf, jsize bufLen, jsize *nVMs);
  auto JNI_GetCreatedJavaVMs = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(addr);
  JavaVM *vm = nullptr;
  jsize nVMs = 0;
  JNI_GetCreatedJavaVMs(&vm, 1, &nVMs);
  // logd("[*] vm -> %p | nVMs -> %d", vm, nVMs);

  if (vm == nullptr) {
    logd("[!] JNI_GetCreatedJavaVMs failed");
    return;
  }

  JNI_OnLoad(vm, nullptr);
}

#endif