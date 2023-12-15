//SPDX-License-Identifier: GPL-2.0
package me.phh.ims

class Rnnoise : AutoCloseable {
    companion object {
        init {
            System.loadLibrary("rnnoise_jni")
        }
    }

    external fun init(): Long
    external fun processFrame(st: Long, frame: ByteArray, out: ByteArray)
    external fun destroy(st: Long)
    external fun getFrameSize(): Int

    var st: Long = init()

    fun processFrame(input: ByteArray, out: ByteArray) {
        // TODO: Check alignment
        // Loop over frames
        val frameSize = getFrameSize()
        for(i in 0 until input.size / (2*frameSize)) {
            val inSlice = input.sliceArray(2*i * frameSize until 2*(i + 1) * frameSize)
            val outSlice = out.sliceArray(2*i * frameSize until 2*(i + 1) * frameSize)
            //android.util.Log.e("PHH", "Processing frame $i ${inSlice.size} ${outSlice.size}")
            processFrame(st, inSlice, outSlice)
        }
    }

    override fun close() {
        destroy(st)
        st = 0
    }
}
