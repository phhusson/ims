#include <jni.h>
#include <android/log.h>
#include <stdint.h>
#include <rnnoise.h>

static float infArray[480];
static float outfArray[480];
JNIEXPORT void JNICALL Java_me_phh_ims_Rnnoise_processFrame(JNIEnv *env, jclass clazz, jlong st, jbyteArray in, jbyteArray out) {
    jboolean isCopy;
    DenoiseState *state = (DenoiseState *) st;
    jbyte *inArray = (*env)->GetByteArrayElements(env, in, &isCopy);
    jbyte *outArray = (*env)->GetByteArrayElements(env, out, &isCopy);
    uint16_t *inArray16 = (uint16_t *) inArray;

    float average = 0;
    for (int i = 0; i < 480; i++) {
        infArray[i] = inArray16[i] / 32768.0f;
        average += infArray[i];
    }
    //__android_log_print(ANDROID_LOG_INFO, "Rnnoise", "Average: %f", average / 480.0f);
    rnnoise_process_frame(state, outfArray, infArray);

    for (int i = 0; i < 480; i++) {
        outfArray[i] = infArray[i];
    }

    uint16_t *outArray16 = (uint16_t *) outArray;
    for (int i = 0; i < 480; i++) {
        outArray16[i] = outfArray[i] * 32768.0f;
    }
    (*env)->ReleaseByteArrayElements(env, in, inArray, 0);
    (*env)->ReleaseByteArrayElements(env, out, outArray, 0);
}

JNIEXPORT jlong Java_me_phh_ims_Rnnoise_init(JNIEnv *env, jclass clazz) {
    DenoiseState  *st = rnnoise_create(NULL);
    return (jlong) st;
}

JNIEXPORT void Java_me_phh_ims_Rnnoise_destroy(JNIEnv *env, jclass clazz, jlong st) {
    DenoiseState *state = (DenoiseState *) st;
    rnnoise_destroy(state);
}

JNIEXPORT int Java_me_phh_ims_Rnnoise_getFrameSize(JNIEnv *env, jclass clazz) {
    return rnnoise_get_frame_size();
}
