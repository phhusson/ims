package me.phh.sip

import android.telephony.Rlog
import java.io.BufferedInputStream
import java.io.InputStream

/* read helper: BufferedReader is character encoded,
 * but we deal with arbitrary binary content in message bodies
 * so we cannot use it.
 * For similar reason, none of the native reader types can be used,
 * so here's a new one...
 */

fun InputStream.sipReader(): SipReader = SipReader(this)

@OptIn(ExperimentalStdlibApi::class)
class SipReader(private val input: InputStream) : BufferedInputStream(input) {
    companion object {
        val TAG = "PHH SipReader"
    }

    //  internal buffer size is not exposed but default is 2k so
    //  just pick something smaller
    var markLength = 1024

    fun continueToNextLine(): Boolean {
        // peak at next line to decide if we got a continuation or not
        // since we didn't get an empty line yet there should be more
        // available to read without extra blocking
        mark(markLength)
        var continuation = false
        while (true) {
            when (read()) {
                ' '.code,
                '\t'.code -> {
                    mark(markLength)
                    continuation = true
                }
                else -> {
                    reset()
                    return continuation
                }
            }
        }
    }

    fun readLine(): String? {
        // we can use the underlying 'buf' from BufferedInputStream:
        //  - buf = buffer
        //  - count = first invalid offset
        //  - pos = current position in buffer (index of next char to be read)
        //  - markpos = position when we did mark
        //  To keep the algorithm simple we just check bytes one at a time
        //  through read(), then take a slice from buf[markpos..pos]
        //  adjusting as appropriate. The buffer is thanksfully not used as a
        //  ring buffer internally so this is safe.

        mark(markLength)
        var line = ByteArray(0)
        while (true) {
            when (read()) {
                -1 -> {
                    Rlog.d(TAG, "Got end of file/buffer")
                    // we could try to return whatever we read until this point,
                    // but that really means we got an invalid message (end of input too early)
                    // so just return null
                    return null
                }
                '\n'.code -> {
                    var lineEnd = pos - 2
                    if (lineEnd >= markpos && buf[lineEnd] == '\r'.toByte()) lineEnd--
                    if (lineEnd < markpos) return null

                    line += buf.slice(markpos..lineEnd)
                    if (!continueToNextLine()) break
                    // check ate extra whitespaces, add a single space to our buffer
                    // and continue appending to it
                    line += ' '.toByte()
                }
            }
        }

        if (line.size == 0) return null

        return String(line, Charsets.US_ASCII)
    }

    fun readNBytes2(len: Int): ByteArray {
        // similar to inputStream readNBytes, loop if required
        // but abort if we did not read full
        var bytes = ByteArray(len)
        var read = 0
        while (read < len) {
            val n = read(bytes, read, len - read)
            if (n < 0) throw Exception("Early end of buffer")
            read += n
        }
        return bytes
    }
}

// lineSequence copied verbatim from kotlin sources, applies to SipReader.
// libraries/stdlib/jvm/src/kotlin/io/ReadWrite.kt

public fun SipReader.lineSequence(): Sequence<String> = LinesSequence(this).constrainOnce()

private class LinesSequence(private val reader: SipReader) : Sequence<String> {
    override public fun iterator(): Iterator<String> {
        return object : Iterator<String> {
            private var nextValue: String? = null
            private var done = false

            override public fun hasNext(): Boolean {
                if (nextValue == null && !done) {
                    nextValue = reader.readLine()
                    if (nextValue == null) done = true
                }
                return nextValue != null
            }

            override public fun next(): String {
                if (!hasNext()) {
                    throw NoSuchElementException()
                }
                val answer = nextValue
                nextValue = null
                return answer!!
            }
        }
    }
}
