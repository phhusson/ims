package me.phh.ims

import kotlin.random.Random

/* type definitions */

enum class SipMethod {
    REGISTER,
    SUBSCRIBE,
    INVITE,
    ACK,
    CANCEL,
    BYE,
    OPTIONS,
    MESSAGE,
}

data class SipStatusCode(val code: Int)

typealias SipHeader = String

typealias SipHeadersMap = Map<String, List<SipHeader>>

sealed class SipMessage()

fun randomHexString(bytes: Int): String =
    Random.Default.nextBytes(bytes).map { String.format("%02x", it) }.joinToString("")

open class SipCommonMessage(
    val firstLine: String,
    private val headersParam: SipHeadersMap,
    // TODO: messageBody needs to handle multipart, including nested multipart,
    // so needs to be a tree of sort? We can probably flatten it into
    // Map<String, List<ByteArray>> where first string is content type?
    // (second part list because there could be multiple of the same
    // and map doesn't allow duplicates)
    // See RFC5621 section 3
    val body: ByteArray? = null,
    private val autofill: Boolean = true,
) : SipMessage() {
    val headers: SipHeadersMap
    init {
        headers = if (autofill) completeHeaders() else headersParam
    }
    // serialize message for sending
    fun toByteArray(): ByteArray =
        this.headers
            .asSequence()
            .fold(
                emptyList<String>(),
                { lines, (header, values) -> lines + values.map { "$header: ${it.toString()}" } }
            )
            .map { it.toByteArray() }
            .plus(listOf(ByteArray(0), this.body ?: ByteArray(0)))
            .fold(this.firstLine.toByteArray(), { msg, line -> msg + "\r\n".toByteArray() + line })

    override fun toString(): String = String(toByteArray(), Charsets.US_ASCII)

    private fun completeHeaders(): SipHeadersMap {
        /* some headers can be automatically generated:
         * - Content-Length (rfc3261 section 20.14)
         * - Call-ID if not already set
         * - 'tag' in 'From' if not already set (rfc3261 section 19.3)
         * - 'branch' in 'Via' if not already set (rfc3261 section 20.42)
         * - Max-Forwards
         *
         * return map as mutable because request/response code piles up
         * a few more headersParam before casting it to unmutable
         */
        val newHeaders = mutableMapOf<String, List<SipHeader>>()
        if (headersParam["content-length"] == null) {
            newHeaders["content-length"] = listOf((this.body?.size ?: 0).toString())
        }
        if (headersParam["call-id"] == null) {
            newHeaders["call-id"] = listOf(randomHexString(12))
        }
        if (headersParam["max-forwards"] == null) {
            newHeaders["max-forwards"] = listOf("70")
        }
        if (headersParam["user-agent"] == null) {
            newHeaders["user-agent"] = listOf("phh ims 0.1")
        }
        val from = headersParam["from"]
        if (from != null) {
            newHeaders["from"] =
                from.map {
                    if (it.contains(";tag=")) {
                        it
                    } else {
                        "$it;tag=${randomHexString(6)}"
                    }
                }
        }
        val via = headersParam["via"]
        if (via != null) {
            newHeaders["via"] =
                via.map {
                    if (it.contains(";branch=")) {
                        it
                    } else {
                        "$it;branch=z9hG4bK${randomHexString(6)}"
                    }
                }
        }
        return headersParam + newHeaders
    }
}

data class SipRequest(
    val method: SipMethod,
    val destination: String,
    private val headersParam: SipHeadersMap,
    private val body: ByteArray? = null,
    private val autofill: Boolean = true,
) : SipMessage() {
    val message: SipCommonMessage
    init {
        val headers = if (autofill) completeRequestHeaders() else headersParam

        message =
            SipCommonMessage(
                firstLine = "$method $destination SIP/2.0",
                headersParam = headers,
                body = body,
                autofill = autofill,
            )
    }

    fun completeRequestHeaders(): SipHeadersMap {
        val newHeaders = mutableMapOf<String, List<SipHeader>>()

        if (headersParam["cseq"] == null) {
            newHeaders["cseq"] = listOf("1 ${this.method}")
        }

        return headersParam + newHeaders
    }
    fun toByteArray(): ByteArray = message.toByteArray()
    override fun toString(): String = message.toString()
}

data class SipResponse(
    val statusCode: SipStatusCode,
    val statusString: String,
    private val headersParam: SipHeadersMap,
    private val body: ByteArray? = null,
    private val autofill: Boolean = true,
) : SipMessage() {
    val message: SipCommonMessage
    init {
        message =
            SipCommonMessage(
                firstLine = "SIP/2.0 $statusCode $statusString",
                headersParam = headersParam,
                body = body,
                autofill = autofill,
            )
    }
    fun toByteArray(): ByteArray = message.toByteArray()
    override fun toString(): String = message.toString()
}

/* rfc3261 section 7 describes how headers should be formed, in particular:
 *  - spaces around : are ignored
 *  - multilines headers are allowed, continuation lines start with a space or tab
 *    and should be joined with a single space
 *  - some headers are comma separated lists, multiple occurence of these headers
 *    is identical to having separated values on single line
 *  - some headers have parameters split by ;
 *  - headers and parameters are case-insensitive
 */
private val splitHeader = "^\\s*([^:]+)\\s*:\\s*(.+)$".toRegex()
private val splitComma = "(<[^>]*>|[^,<]+)+".toRegex()
private val splitSemiColumn = "(<[^>]*>|[^;<]+)+".toRegex()
private val splitParam = "^([^=]+)=?(.*)".toRegex()

fun sipHeaderOf(line: String): Pair<String, List<SipHeader>>? {
    val (headerRaw, valueRaw) = splitHeader.find(line)?.destructured ?: return null
    val header =
        when (val headerLowCase = headerRaw.lowercase()) {
            // translate compact form to normal
            "i" -> "call-id"
            "m" -> "contact"
            "e" -> "content-encoding"
            "l" -> "content-length"
            "c" -> "content-type"
            "f" -> "from"
            "s" -> "subject"
            "k" -> "supported"
            "t" -> "to"
            "v" -> "via"
            else -> headerLowCase
        }
    val values =
        when (header) {
            "contact",
            "to",
            "from",
            "allow",
            "p-asserted-identity",
            "supported" -> splitComma.findAll(valueRaw).toList().map { it.groupValues[0].trim() }
            else -> listOf(valueRaw)
        }

    return header to values
}

fun SipHeader.getParams(): Pair<String, Map<String, String?>> {
    val paramSplit = splitSemiColumn.findAll(this).toList().map { it.groupValues[0].trim() }
    return paramSplit[0] to
        paramSplit
            .slice(1..paramSplit.size - 1)
            .map Map@{
                val (a, b) = splitParam.find(it)?.destructured ?: return@Map it.lowercase() to null
                a.lowercase() to b.lowercase()
            }
            .toMap()
}

fun String.toSipHeadersMap(): SipHeadersMap = this.lines().mapNotNull(::sipHeaderOf).toMap()

fun SipReader.parseHeaders(): SipHeadersMap =
    this.lineSequence()
        .fold(
            emptyMap<String, List<SipHeader>>(),
            fold@{ headers, line ->
                val (header, value) = sipHeaderOf(line) ?: return@fold headers
                val oldVal = headers.get(header) ?: emptyList<SipHeader>()

                headers + (header to oldVal + value)
            }
        )

fun SipReader.parseMessage(): SipMessage? {
    val firstLine = this.readLine() ?: return null
    val headers = this.parseHeaders()
    val body = headers["content-length"]?.getOrNull(0)?.toInt()?.let { this.readNBytes(it) }
    // TODO: parse body depending on content type (e.g. multipart)
    val firstLineSplit = firstLine.split(" ")
    when (firstLineSplit[0]) {
        // TODO: also check last element in line is SIP/2.0?
        "REGISTER" ->
            return SipRequest(
                method = SipMethod.REGISTER,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "SUBSCRIBE" ->
            return SipRequest(
                method = SipMethod.SUBSCRIBE,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "INVITE" ->
            return SipRequest(
                method = SipMethod.INVITE,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "ACK" ->
            return SipRequest(
                method = SipMethod.ACK,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "CANCEL" ->
            return SipRequest(
                method = SipMethod.CANCEL,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "BYE" ->
            return SipRequest(
                method = SipMethod.BYE,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "OPTIONS" ->
            return SipRequest(
                method = SipMethod.OPTIONS,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "MESSAGE" ->
            return SipRequest(
                method = SipMethod.MESSAGE,
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "SIP/2.0" -> {
            val code = firstLineSplit.getOrNull(1)?.toInt() ?: return null
            return SipResponse(
                statusCode = SipStatusCode(code),
                statusString = firstLineSplit.getOrNull(2) ?: "",
                headersParam = headers,
                body = body,
                autofill = false,
            )
        }
        else ->
            return SipCommonMessage(
                firstLine = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
    }
}
