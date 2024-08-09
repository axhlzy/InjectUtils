//
// Created by lzy on 2023/6/15.
//

#ifndef IL2CPPHOOKER_PINE_H
#define IL2CPPHOOKER_PINE_H

#include <jni.h>
#include <string>

namespace Pine {

    static bool isInitialized = false;

    class CallFrame {

    private:
        jobject self;
        JNIEnv *env;

    public:
        CallFrame(JNIEnv *env, jobject self) : env(env), self(self) {};

        jobject getMethod();

        std::string getMethodToString();

        jobject getThisObject();

        jobjectArray getArgs();

        jobject getArg(int index);

        void setArg(int index, jobject arg);

        int getArgCount();

        // public Object getResult()
        jobject getResult();

        // public void setResult(Object result)
        void setResult(jobject result);

        // public Throwable getThrowable()
        jobject getThrowable();

        // public boolean hasThrowable()
        jboolean hasThrowable();

        // public void setThrowable(Throwable throwable)
        void setThrowable(jobject throwable);

        // public Object getResultOrThrowable()
        jobject getResultOrThrowable();

        // public void resetResult()
        void resetResult();

        // public Object invokeOriginalMethod() throws InvocationTargetException, IllegalAccessException
        jobject invokeOriginalMethod();

        // public Object invokeOriginalMethod(Object thisObject, Object... args) throws InvocationTargetException, IllegalAccessException
        jobject invokeOriginalMethod(jobject thisObject, jobjectArray args);

        // self instance toString
        std::string toString();

        /**
         * 格式化输出函数调用的基本信息
         * 注意：由于此函数用到了函数返回值，故必须在onLevel中调用
         * @return
         */
        std::string toValueString();
    };

    static auto NOP_FUNC = [](JNIEnv *, CallFrame *) {};

    /**
     * PineInit 初始化 (使用PineHook前必要的调用)
     * @param vm Java VM*
     * @param reserved JNI reserved
     * @param env JNI env*
     */
    bool PineInit(JavaVM *vm, void *reserved, JNIEnv *env);

    /**
     * 添加一个 java method hook
     * @param className 类名
     * @param methodName 方法名
     * @param methodSig 方法签名
     * @param onEnter 函数进入时候的回调函数，用来修改函数入参
     * @param onLevel 函数返回时候的回调函数，用来修改函数返回值
     * @example :
     *   Pine::registerMethodHook("com/blankj/utilcode/util/TimeUtils", "getNowString", "()Ljava/lang/String;",
                [](JNIEnv *env, Pine::CallFrame *callFrame) {
                    LOGD("hook TimeUtils.getNowString onEnter \n\t{}", callFrame->getMethodToString());
                },
                [](JNIEnv *env, Pine::CallFrame *callFrame) {
                    LOGD("hook TimeUtils.getNowString onLevel \n\t{}",JNIHelper::toString(callFrame->getResult()));
                    callFrame->setResult(env->NewStringUTF("hook TimeUtils.getNowString"));
                });
     */
    void registerMethodHook(const std::string &className, const std::string &methodName, const std::string &methodSig,
                            const function<void(JNIEnv *, CallFrame *)> &onEnter = NOP_FUNC,
                            const function<void(JNIEnv *, CallFrame *)> &onLevel = NOP_FUNC);

    /**
     * 添加一个 java method hook
     * @param reflect_method java method
     * @param onEnter 函数进入时候的回调函数，用来修改函数入参
     * @param onLevel 函数返回时候的回调函数，用来修改函数返回值
     */
    void registerMethodHook(jobject reflect_method,
                            const function<void(JNIEnv *, CallFrame *)> &onEnter = NOP_FUNC,
                            const function<void(JNIEnv *, CallFrame *)> &onLevel = NOP_FUNC);

    /**
     * 添加一个 java class hook
     * @param className 类名
     * @param classLoader 子类加载器，如果为null则使用系统类加载器
     * @param onEnter 函数进入时候的回调函数，用来修改函数入参
     * @param onLevel 函数返回时候的回调函数，用来修改函数返回值
     * @param passMethods 跳过的方法 可选参数
     * @example :
     *     Pine::registerClassHook("com/blankj/utilcode/util/Utils", nullptr,
                       [](JNIEnv *env, Pine::CallFrame *callFrame) {
                           LOGD("onEnter \n\t{}", callFrame->getMethodToString());
                       },
                       [](JNIEnv *env, Pine::CallFrame *callFrame) {
                       });
     */
    void registerClassHook(const std::string &className, jobject classLoader = nullptr,
                           const function<void(JNIEnv *, CallFrame *)> &onEnter = NOP_FUNC,
                           const function<void(JNIEnv *, CallFrame *)> &onLevel = NOP_FUNC,
                           vector<std::string> ignoreMethods = {});

    // linker -> link
    jobject Pine_hook0(JNIEnv *env, jclass, jlong threadAddress, jclass declaring, jobject javaTarget,
                       jobject javaBridge, jboolean isInlineHook, jboolean isJni);

    extern "C" jint Pine_JNI_OnLoad(JavaVM *vm, void *reserved);
}

extern "C"
    __attribute__((used))
    JNIEXPORT void JNICALL
    Java_top_canyie_pine_Pine_beforeCallN(JNIEnv *env, jclass clazz, jobject call_frame);

extern "C"
    __attribute__((used))
    JNIEXPORT void JNICALL
    Java_top_canyie_pine_Pine_afterCallN(JNIEnv *env, jclass clazz, jobject call_frame);

#endif // IL2CPPHOOKER_PINE_H
