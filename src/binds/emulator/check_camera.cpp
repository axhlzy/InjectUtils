#include "mSyscall.h"
#include <iostream>
#include <jni.h>

extern jobject g_application;

void check_camera(JNIEnv *env) {
    jobject context = g_application;
    std::cout << "check_camera context" << (context) << std::endl;

    // Get CameraManager service
    jstring cameraType = env->NewStringUTF("camera");
    jobject objService = env->CallObjectMethod(
        context,
        env->GetMethodID(env->GetObjectClass(context), "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;"),
        cameraType);
    env->DeleteLocalRef(cameraType);

    std::cout << "check_camera objService" << (objService) << std::endl;

    // Get list of camera IDs
    jobjectArray cameraList = static_cast<jobjectArray>(env->CallObjectMethod(
        objService,
        env->GetMethodID(env->GetObjectClass(objService), "getCameraIdList", "()[Ljava/lang/String;")));

    std::cout << "check_camera cameraList" << (cameraList) << std::endl;

    // Get the length of the camera list
    jsize cameraCount = env->GetArrayLength(cameraList);
    std::cout << "check_camera cameraCount" << (cameraCount) << std::endl;

    if (cameraCount < 2) {
        // TODO: Consider non-real device environment if camera count is less than 2
    }
}