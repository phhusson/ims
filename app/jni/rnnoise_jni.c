#include <jni.h>
#include <android/log.h>
#include <stdint.h>
#include <rnnoise.h>

static float infArray[480];
static float outfArray[480];
JNIEXPORT void JNICALL Java_me_phh_ims_Rnnoise_processFrame(JNIEnv *env, jclass clazz, jlong st, jbyteArray in, jbyteArray out) {
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A1 %p %lx %p %p", clazz, st, in, out);
    jboolean isCopy;
    DenoiseState *state = (DenoiseState *) st;
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A2");
    int len = (*env)->GetArrayLength(env, in);
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A2.2 %d", len);
    jbyte *inArray = (*env)->GetByteArrayElements(env, in, &isCopy);
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A3");
    len = (*env)->GetArrayLength(env, out);
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A3.2 %d", len);
    jbyte *outArray = (*env)->GetByteArrayElements(env, out, &isCopy);
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A4");
    uint16_t *inArray16 = (uint16_t *) inArray;
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A5");

    for (int i = 0; i < 480; i++) {
        infArray[i] = inArray16[i] / 32768.0f;
    }
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A8");
    //rnnoise_process_frame(state, outfArray, infArray);

    for (int i = 0; i < 480; i++) {
        outfArray[i] = infArray[i];
    }

    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A9");
    uint16_t *outArray16 = (uint16_t *) outArray;
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A10");
    for (int i = 0; i < 480; i++) {
        outArray16[i] = outfArray[i] * 32768.0f;
    }
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A11");
    (*env)->ReleaseByteArrayElements(env, in, inArray, 0);
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A12");
    (*env)->ReleaseByteArrayElements(env, out, outArray, 0);
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "A13");
}

JNIEXPORT jlong Java_me_phh_ims_Rnnoise_init(JNIEnv *env, jclass clazz) {
    //DenoiseState  *st = rnnoise_create(NULL);
    DenoiseState  *st = NULL;
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "B1 %p", st);
    return (jlong) st;
}

JNIEXPORT void Java_me_phh_ims_Rnnoise_destroy(JNIEnv *env, jclass clazz, jlong st) {
    __android_log_print(ANDROID_LOG_WARN, "PHH-Rnnoise", "Destroying denoise state %lx", st);
    //DenoiseState *state = (DenoiseState *) st;
    //rnnoise_destroy(state);
}

JNIEXPORT int Java_me_phh_ims_Rnnoise_getFrameSize(JNIEnv *env, jclass clazz) {
    return rnnoise_get_frame_size();
}
