//
// Created by lzy on 2023/6/16.
//

#include "Pine.h"

#include "modules/jnihelper/JNIHelper.h"
#include "modules/dex/DexManager.h"
#include "PineDexToBase64.h"

using namespace Pine;

static std::shared_ptr<spdlog::logger> logger;

static jobject PineDexClassLoader = nullptr;

// reflected method as key , two callback function as value
static map<string , pair<function<void(JNIEnv *, CallFrame *)>, function<void(JNIEnv *, CallFrame *)>>> hookList;
// global ref class
static jclass clazz_Pine;
static jclass clazz_PineConfig;
static jclass clazz_CallFrame;

bool Pine::PineInit(JavaVM *vm, void *reserved, JNIEnv *env) {
    INIT_LOGGER();
    PineDexClassLoader = Global<DexManager>::Get()->LoadDex(Pine::DEX, true);
    if (PineDexClassLoader == nullptr) {
        LOGE("PineDexClassLoader is null");
        return false;
    }
    Pine_JNI_OnLoad(vm, reserved);
    LOGT("PineDex -> {}", JNIHelper::toString(PineDexClassLoader));

    clazz_PineConfig = JNIHelper::LoadClass(AY_OBFUSCATE("top/canyie/pine/PineConfig"), PineDexClassLoader);

#ifdef DEBUG_PROJECT
    auto field_debug = env->GetStaticFieldID(clazz_PineConfig, AY_OBFUSCATE("debug"), AY_OBFUSCATE("Z"));
    env->SetStaticBooleanField(clazz_PineConfig, field_debug, true);
    auto field_debuggable = env->GetStaticFieldID(clazz_PineConfig, AY_OBFUSCATE("debuggable"), AY_OBFUSCATE("Z"));
    env->SetStaticBooleanField(clazz_PineConfig, field_debuggable, true);
#endif

    Java_top_canyie_pine_Pine_beforeCallN(env, nullptr, nullptr);
    Java_top_canyie_pine_Pine_afterCallN(env, nullptr, nullptr); // 保证不被编译器优化删除

    // top.canyie.pine.Pine -> public static boolean isInitialized()
    clazz_Pine = JNIHelper::LoadClass(AY_OBFUSCATE("top/canyie/pine/Pine"), PineDexClassLoader);
    clazz_CallFrame = JNIHelper::LoadClass(AY_OBFUSCATE("top.canyie.pine.Pine$CallFrame"), PineDexClassLoader);

    //  public static void ensureInitialized()
    auto method_ensureInitialized = env->GetStaticMethodID(clazz_Pine, AY_OBFUSCATE("ensureInitialized"), AY_OBFUSCATE("()V"));
    env->CallStaticVoidMethod(clazz_Pine, method_ensureInitialized);

    auto method_isInitialized = env->GetStaticMethodID(clazz_Pine, AY_OBFUSCATE("isInitialized"), AY_OBFUSCATE("()Z"));
    isInitialized = (jboolean)env->CallStaticBooleanMethod(clazz_Pine, method_isInitialized);
    LOGD("Pine isInitialized -> {}", isInitialized);
    return isInitialized;
}

extern "C" void
Java_top_canyie_pine_Pine_beforeCallN(JNIEnv *env, jclass clazz, jobject call_frame) {
    if (clazz == nullptr || call_frame == nullptr) return;
    auto* callFrame = new CallFrame(env, call_frame);
    string method_key = callFrame->getMethodToString();
    LOGT("beforeCallN method_key -> {}", method_key);
    auto it_hook = hookList.find(method_key);
    if (it_hook != hookList.end()) {
        auto pair = it_hook->second;
        if (pair.first) {
            LOGT("beforeCallN FoundCallback Before -> {}", typeid(pair.first).name());
            pair.first(env, callFrame);
        }
    }
    delete callFrame;
}

extern "C" void
Java_top_canyie_pine_Pine_afterCallN(JNIEnv *env, jclass clazz, jobject call_frame) {
    if (clazz == nullptr || call_frame == nullptr) return;
    auto* callFrame = new CallFrame(env, call_frame);
    string method_key = callFrame->getMethodToString();
    LOGT("afterCallN method_key -> {}", method_key);
    auto it_hook = hookList.find(method_key);
    if (it_hook != hookList.end()) {
        auto pair = it_hook->second;
        if (pair.second) {
            LOGT("afterCallN FoundCallback After -> {}", typeid(pair.second).name());
            pair.second(env, callFrame);
        }
    }
    delete callFrame;
}

void Pine::registerMethodHook(const string& className, const string& methodName, const string& methodSig,
                              const function<void(JNIEnv *, CallFrame *)>& onEnter,
                              const function<void(JNIEnv *, CallFrame *)>& onLevel) {
    INIT_LOGGER();

    if (!Pine::isInitialized){
        LOGE("Called registerMethodHook before PineInit");
        return;
    }

    if (PineDexClassLoader == nullptr) {
        LOGE("Called registerMethodHook after PineInit");
        return;
    }
    auto tmp_class = JNIHelper::LoadClass(className.c_str(), PineDexClassLoader);
    bool isStatic = true;
    jmethodID tmp_method = JNIHelper::mEnv->GetStaticMethodID(tmp_class, methodName.c_str(), methodSig.c_str());
    if (tmp_method == nullptr){
        tmp_method = JNIHelper::mEnv->GetMethodID(tmp_class, methodName.c_str(), methodSig.c_str());
        isStatic = false;
    }
    if (tmp_method == nullptr){
        LOGE("registerMethodHook -> {} {} {} not found", className, methodName, methodSig);
        return;
    } else {
        auto tmp_reflect = JNIHelper::mEnv->ToReflectedMethod(tmp_class, tmp_method, isStatic);
        registerMethodHook(tmp_reflect, onEnter, onLevel);
    }
}

void Pine::registerMethodHook(jobject reflect_method,
                              const function<void(JNIEnv *, CallFrame *)> &onEnter,
                              const function<void(JNIEnv *, CallFrame *)> &onLevel) {
    INIT_LOGGER();
    if (!Pine::isInitialized){
        LOGE("Called registerMethodHook before PineInit");
        return;
    }
    // toString JNIHelper::toString(tmp_reflect) === new CallFrame(env, call_frame).getMethodToString()
    auto currentClassName = JNIHelper::toString(reflect_method);
    if (currentClassName.find("abstract")!=string::npos) {
        LOGW("registerMethodHook pass -> {} is abstract", currentClassName);
        return;
    }
    LOGD("HOOK -> {}", currentClassName);
    // save reflect method and callback function ↘
    hookList.emplace(JNIHelper::toString(reflect_method), make_pair(onEnter, onLevel));
    auto method_addHookMethod = JNIHelper::mEnv->GetStaticMethodID(clazz_Pine, AY_OBFUSCATE("addHookMethod"), AY_OBFUSCATE("(Ljava/lang/reflect/Member;)V"));
    // start hook ↘
    JNIHelper::mEnv->CallStaticVoidMethod(clazz_Pine, method_addHookMethod, reflect_method);
}

void Pine::registerClassHook(const string & className, jobject classLoader,
                             const function<void(JNIEnv *, CallFrame *)> &onEnter,
                             const function<void(JNIEnv *, CallFrame *)> &onLevel,
                             vector<string> ignoreMethods) {
    classLoader = classLoader == nullptr ? PineDexClassLoader : classLoader;
    auto localClassName = className;

    std::replace(localClassName.begin(), localClassName.end(), '.', '/');
    vector<tuple<jobject , string, string>> methods = JNIHelper::getMethods(localClassName, classLoader);

    std::replace(localClassName.begin(), localClassName.end(), '/', '.');
    for (auto method : methods) {
        jobject current_reflect = get<0>(method);
        auto currentMethodStr = JNIHelper::toString(current_reflect);
        if (currentMethodStr.find(localClassName) == string::npos) continue;
        auto found = std::find_if(ignoreMethods.begin(), ignoreMethods.end(),
                                  [&currentMethodStr](const string& str) {
                                      return currentMethodStr.find(str) != string::npos;
                                  });
        if (found == ignoreMethods.end()) Pine::registerMethodHook(current_reflect, onEnter, onLevel);
    }
}

jobject CallFrame::getResult() {
    // public Object getResult()
    return env->CallObjectMethod(self, env->GetMethodID(clazz_CallFrame, "getResult", "()Ljava/lang/Object;"));
}

void CallFrame::setResult(jobject result) {
    // public void setResult(Object result)
    env->CallVoidMethod(self, env->GetMethodID(clazz_CallFrame, "setResult", "(Ljava/lang/Object;)V"), result);
}

jobject CallFrame::getThrowable() {
    // public Throwable getThrowable()
    return env->CallObjectMethod(self, env->GetMethodID(clazz_CallFrame, "getThrowable", "()Ljava/lang/Throwable;"));
}

jboolean CallFrame::hasThrowable() {
    return env->CallBooleanMethod(self, env->GetMethodID(clazz_CallFrame, "hasThrowable", "()Z"));
}

void CallFrame::setThrowable(jobject throwable) {
    // public void setThrowable(Throwable throwable)
    env->CallVoidMethod(self, env->GetMethodID(clazz_CallFrame, "setThrowable", "(Ljava/lang/Throwable;)V"), throwable);
}

jobject CallFrame::getResultOrThrowable() {
    return env->CallObjectMethod(self, env->GetMethodID(clazz_CallFrame, "getResultOrThrowable", "()Ljava/lang/Object;"));
}

void CallFrame::resetResult() {
    // public void resetResult()
    env->CallVoidMethod(self, env->GetMethodID(clazz_CallFrame, "resetResult", "()V"));
}

jobject CallFrame::invokeOriginalMethod() {
    //  public Object invokeOriginalMethod() throws InvocationTargetException, IllegalAccessException
    return env->CallObjectMethod(self, env->GetMethodID(clazz_CallFrame, "invokeOriginalMethod", "()Ljava/lang/Object;"));
}

jobject CallFrame::invokeOriginalMethod(jobject thisObject, jobjectArray args) {
    return env->CallObjectMethod(self, env->GetMethodID(clazz_CallFrame, "invokeOriginalMethod", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), thisObject, args);
}

jobject CallFrame::getMethod() {
    // public final Member method;
    return env->GetObjectField(self, env->GetFieldID(clazz_CallFrame, "method", "Ljava/lang/reflect/Member;"));
}

string CallFrame::getMethodToString() {
    return JNIHelper::toString(getMethod());
}

jobject CallFrame::getThisObject() {
    // public Object thisObject;
    return env->GetObjectField(self, env->GetFieldID(clazz_CallFrame, "thisObject", "Ljava/lang/Object;"));
}

jobjectArray CallFrame::getArgs() {
    // public Object[] args;
    return (jobjectArray)env->GetObjectField(self, env->GetFieldID(clazz_CallFrame, "args", "[Ljava/lang/Object;"));
}

jobject CallFrame::getArg(int index) {
    int argC = getArgCount();
    if (index < 0 || index >= argC) {
        LOGE("getArg index out of bounds: index = {} | {} > index ≥ {} ", index, argC, 0);
        return nullptr;
    }
    return env->GetObjectArrayElement(getArgs(), index);
}

void CallFrame::setArg(int index, jobject arg) {
    int argC = getArgCount();
    if (index < 0 || index >= argC) {
        LOGE("setArg index out of bounds: index = {} | {} > index ≥ {} ", index, argC, 0);
        return;
    }
    env->SetObjectArrayElement(getArgs(), index, arg);
}

int CallFrame::getArgCount() {
    return env->GetArrayLength(getArgs());
}

string CallFrame::toString() {
    return JNIHelper::toString(self);
}

string CallFrame::toValueString() {
    int count = getArgCount();
    stringstream ss;
    ss << "CallFrame { method=" << getMethodToString() << ", thisObject=" << JNIHelper::toString(getThisObject()) << ", args=[";
    for (int i = 0; i < count; ++i) {
        ss << "'" << JNIHelper::toString(getArg(i)) << "'";
        if (i != count - 1) ss << ", ";
    }
    ss << "] , ";
    ss << "ret=>['" << JNIHelper::toString(getResultOrThrowable()) << "'] }";
    return ss.str();
}