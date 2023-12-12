#include <jni.h>
#include <rnnoise.h>

JNIEXPORT void Java_me_phh_ims_Rnnoise_processFrame(JNIEnv *env, jclass clazz, jlong st, jbyteArray in, jbyteArray out) {
    DenoiseState *state = (DenoiseState *) st;
    jshort *inArray = (*env)->GetShortArrayElements(env, in, NULL);
    jshort *outArray = (*env)->GetShortArrayElements(env, out, NULL);
    rnnoise_process_frame(state, outArray, inArray);
    (*env)->ReleaseShortArrayElements(env, in, inArray, 0);
    (*env)->ReleaseShortArrayElements(env, out, outArray, 0);
}

JNIEXPORT jlong Java_me_phh_ims_Rnnoise_init(JNIEnv *env, jclass clazz) {
    return (jlong) rnnoise_create(NULL);
}

JNIEXPORT void Java_me_phh_ims_Rnnoise_destroy(JNIEnv *env, jclass clazz, jlong st) {
    DenoiseState *state = (DenoiseState *) st;
    rnnoise_destroy(state);
}

JNIEXPORT int Java_me_phh_ims_Rnnoise_getFrameSize(JNIEnv *env, jclass clazz) {
    return rnnoise_get_frame_size();
}
