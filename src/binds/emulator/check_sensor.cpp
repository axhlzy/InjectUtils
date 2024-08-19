#include <iostream>
#include <jni.h>

extern jobject g_application;

void check_sensor(JNIEnv *env) {
    jobject context = g_application;
    std::cout << "check_sensor context " << context << std::endl;

    // Get SensorManager service
    jstring sensorType = env->NewStringUTF("sensor");
    jobject objService = env->CallObjectMethod(
        context,
        env->GetMethodID(env->GetObjectClass(context), "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;"),
        sensorType);
    env->DeleteLocalRef(sensorType);

    std::cout << "check_sensor objService " << objService << std::endl;

    // Get list of sensors
    jobject sensorList = env->CallObjectMethod(
        objService,
        env->GetMethodID(env->GetObjectClass(objService), "getSensorList", "(I)Ljava/util/List;"),
        -1);

    std::cout << "check_sensor sensorList " << sensorList << std::endl;

    // Check the size of the sensor list
    jint sensorCount = env->CallIntMethod(sensorList, env->GetMethodID(env->GetObjectClass(sensorList), "size", "()I"));
    std::cout << "check_sensor sensorCount " << sensorCount << std::endl;

    if (sensorCount < 20) {
        // TODO: Consider non-real device environment if sensor count is less than 20
    }
}