package me.phh.sip

import org.junit.Test

val simple = """
    line1
    line2
    """.trimIndent().replace("\n", "\r\n") + "\r\n\r\n"

val lineContinuation =
    """
    line1
       line2 continued
    """.trimIndent().replace("\n", "\r\n") + "\r\n\r\n"

val multipleMessages =
    """
    line1
    line2

    line1 again
    """.trimIndent().replace("\n", "\r\n") + "\r\n\r\n"

val binaryData = byteArrayOf(2, 0, 0x41, 2, 0, 0)
val trailingData =
    """
    line1
    line2
    """.trimIndent().replace("\n", "\r\n") +
        "\r\n\r\n" +
        String(binaryData)

class SipReaderTests {
    @Test
    fun `simple read lines`() {
        val reader = simple.toByteArray().inputStream().sipReader()
        val line1 = reader.readLine()
        require(line1 == "line1")
        val line2 = reader.readLine()
        require(line2 == "line2")
        val line3 = reader.readLine()
        require(line3 == null)
        val line4 = reader.readLine()
        require(line4 == null)
    }

    @Test
    fun `read line with continuation`() {
        val reader = lineContinuation.toByteArray().inputStream().sipReader()
        val line1 = reader.readLine()
        require(line1 == "line1 line2 continued")
        val line2 = reader.readLine()
        require(line2 == null)
    }

    @Test
    fun `read two messages`() {
        val reader = multipleMessages.toByteArray().inputStream().sipReader()
        val line1 = reader.readLine()
        require(line1 == "line1")
        val line2 = reader.readLine()
        require(line2 == "line2")
        val line3 = reader.readLine()
        require(line3 == null)
        val line4 = reader.readLine()
        require(line4 == "line1 again")
        val line5 = reader.readLine()
        require(line5 == null)
    }

    @Test
    fun `read trailing data`() {
        val reader = trailingData.toByteArray().inputStream().sipReader()
        val sequence = reader.lineSequence()
        require(sequence.toList() == listOf("line1", "line2"))
        val array = ByteArray(6)
        require(reader.read(array) == 6)
        // kotlin arrays are java arrays, and java arrays equals doesn't
        // compare array content.. but it works for slices as these are lists
        // https://discuss.kotlinlang.org/t/bytearray-comparison/1689/12
        require(array.slice(0..array.size - 1) == binaryData.slice(0..binaryData.size - 1))
    }

    @Test
    fun `read two messages with lineSequence`() {
        val reader = multipleMessages.toByteArray().inputStream().sipReader()
        val sequence = reader.lineSequence()
        require(sequence.toList() == listOf("line1", "line2"))
        val sequence2 = reader.lineSequence()
        require(sequence2.toList() == listOf("line1 again"))
    }

    @Test
    fun `read two messages with lineSequence and plain read between`() {
        val reader = multipleMessages.toByteArray().inputStream().sipReader()
        val sequence = reader.lineSequence()
        require(sequence.toList() == listOf("line1", "line2"))
        val array = ByteArray(5)
        require(reader.read(array) == 5)
        require(String(array) == "line1")
        val sequence2 = reader.lineSequence()
        require(sequence2.toList() == listOf(" again"))
    }
}
