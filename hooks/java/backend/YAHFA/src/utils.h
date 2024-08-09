//
// Created by A on 2022/4/26.
//

#ifndef INJECTIL2CPP_UTILS_H
#define INJECTIL2CPP_UTILS_H

#include <jni.h>
#include <android/log.h>
#include <stdint.h>

#include "common.h"

#if defined(__aarch64__)
#include <dlfcn.h>
#include "dlfunc.h"
#define NEED_CLASS_VISIBLY_INITIALIZED
#endif

static int shouldVisiblyInit();
static int findInitClassSymbols(JNIEnv *env);
static int findJavaVmOffsetInRuntime(JavaVM *jvm, void **runtime);

jlong __attribute__((naked))
    Java_lab_galaxy_ZZY_HookMain_00024Utils_getThread(JNIEnv *env, jclass clazz);
jboolean Java_lab_galaxy_ZZY_HookMain_00024Utils_shouldVisiblyInit(JNIEnv *env, jclass clazz);
jint Java_lab_galaxy_ZZY_HookMain_00024Utils_visiblyInit(JNIEnv *env, jclass clazz, jlong thread);


#endif //INJECTIL2CPP_UTILS_H
