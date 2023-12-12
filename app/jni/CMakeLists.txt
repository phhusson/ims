cmake_minimum_required(VERSION 3.4.1)
add_library(
    rnnoise_jni
    SHARED
    rnnoise_jni.c
    rnnoise/src/denoise.c
    rnnoise/src/kiss_fft.c
    rnnoise/src/rnn.c
    rnnoise/src/rnn_data.c
    rnnoise/src/pitch.c
    rnnoise/src/celt_lpc.c)
target_link_libraries(rnnoise_jni PRIVATE m)
target_include_directories(rnnoise_jni PUBLIC rnnoise/include)
