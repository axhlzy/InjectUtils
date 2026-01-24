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

// run on remote
void repl_socket(lua_State *L) {
  logd("[*] start lua repl | Socket Mode | %d", SOCKET_PORT);
  try {
    boost::asio::io_context io_context;
    LuaReplServer server(io_context, SOCKET_PORT, L);
    io_context.run();
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
  }
}

// run on local
void start_local_repl() {
  LuaReplClient client(std::to_string(SOCKET_PORT));
  client.connect();
  // todo getLuaCommands() mem sync with remote process
  installRepl({""}, [&](const std::string &input) {
    if (input == "exit" || input == "q") {
      client.close_connect();
    } else {
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