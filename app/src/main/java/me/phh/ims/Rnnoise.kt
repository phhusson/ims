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

    fun processFrame(frame: ByteArray, out: ByteArray) {
        processFrame(st, frame, out)
    }

    override fun close() {
        destroy(st)
    }
}
