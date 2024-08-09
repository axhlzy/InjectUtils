//
// Created by A on 2022/4/25.
//

#ifndef YAHFA_HOOKMAIN_H
#define YAHFA_HOOKMAIN_H

#include <jni.h>
#include <stdlib.h>

#include "common.h"
#include "trampoline.h"

void Java_lab_galaxy_yahfa_HookMain_init(JNIEnv *env, jclass clazz, jint sdkVersion);

jobject Java_lab_galaxy_yahfa_HookMain_findMethodNative(JNIEnv *env, jclass clazz,
                                                        jclass targetClass, jstring methodName,
                                                        jstring methodSig);

jboolean Java_lab_galaxy_yahfa_HookMain_backupAndHookNative(JNIEnv *env, jclass clazz,
                                                            jobject target, jobject hook,
                                                            jobject backup);

static uint32_t getFlags(char *method);

static void setFlags(char *method, uint32_t access_flags);

static void setNonCompilable(void *method);

static int replaceMethod(void *fromMethod, void *toMethod, int isBackup);

static int doBackupAndHook(void *targetMethod, void *hookMethod, void *backupMethod);

static void *getArtMethod(JNIEnv *env, jobject jmethod);

#endif //YAHFA_HOOKMAIN_H
