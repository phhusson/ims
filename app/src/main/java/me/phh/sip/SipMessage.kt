package me.phh.sip

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

data class SipHeader(val value: String, val parameters: Map<String, String?>) {
    override fun toString(): String =
        this.value +
            this.parameters
                .asSequence()
                .fold(
                    "",
                    { acc, (param, pvalue) ->
                        if (pvalue != null) "$acc;$param=$pvalue" else "$acc;$param"
                    }
                )
}

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
            newHeaders["content-length"] =
                listOf(SipHeader((this.body?.size ?: 0).toString(), emptyMap()))
        }
        if (headersParam["call-id"] == null) {
            newHeaders["call-id"] = listOf(SipHeader(randomHexString(12), emptyMap()))
        }
        if (headersParam["max-forwards"] == null) {
            newHeaders["max-forwards"] = listOf(SipHeader("70", emptyMap()))
        }
        val from = headersParam["from"]
        if (from != null) {
            newHeaders["from"] =
                from.map {
                    if (it.parameters["tag"] != null) {
                        it
                    } else {
                        SipHeader(it.value, it.parameters.plus("tag" to randomHexString(6)))
                    }
                }
        }
        val via = headersParam["via"]
        if (via != null) {
            newHeaders["via"] =
                via.map {
                    if (it.parameters["branch"] != null) {
                        it
                    } else {
                        SipHeader(
                            it.value,
                            it.parameters.plus("branch" to "z9hG4bK" + randomHexString(6))
                        )
                    }
                }
        }
        return headersParam + newHeaders
    }
}

data class SipRequest(
    val method: SipMethod,
    private val firstLineParam: String,
    private val headersParam: SipHeadersMap,
    private val body: ByteArray? = null,
    private val autofill: Boolean = true,
) : SipMessage() {
    val message: SipCommonMessage
    init {
        val headers = if (autofill) completeRequestHeaders() else headersParam

        message =
            SipCommonMessage(
                firstLine = firstLineParam,
                headersParam = headers,
                body = body,
                autofill = autofill,
            )
    }

    fun completeRequestHeaders(): SipHeadersMap {
        val newHeaders = mutableMapOf<String, List<SipHeader>>()

        if (headersParam["cseq"] == null) {
            newHeaders["cseq"] = listOf(SipHeader("1 ${this.method}", emptyMap()))
        }

        return headersParam + newHeaders
    }
}

data class SipResponse(
    val statusCode: SipStatusCode,
    private val firstLineParam: String,
    private val headersParam: SipHeadersMap,
    private val body: ByteArray? = null,
    private val autofill: Boolean = true,
) : SipMessage() {
    val message: SipCommonMessage
    init {
        message =
            SipCommonMessage(
                firstLine = firstLineParam,
                headersParam = headersParam,
                body = body,
                autofill = autofill,
            )
    }
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
    val values =
        when (header) {
            "contact",
            "to",
            "from",
            "allow",
            "p-asserted-identity",
            "supported" -> splitComma.findAll(valueRaw).toList().map { it.groupValues[0].trim() }
            else -> listOf(valueRaw)
        }.map { attr ->
            val (base, parameters) =
                when (header) {
                    "accept-contact",
                    "security-verify",
                    "security-client",
                    "security-server",
                    "contact",
                    "to",
                    "from",
                    "via" -> {
                        val paramSplit =
                            splitSemiColumn.findAll(attr).toList().map { it.groupValues[0].trim() }
                        paramSplit[0] to
                            paramSplit
                                .slice(1..paramSplit.size - 1)
                                .map Map@{
                                    val (a, b) =
                                        splitParam.find(it)?.destructured
                                            ?: return@Map it.lowercase() to ""
                                    a.lowercase() to b.lowercase()
                                }
                                .toMap()
                    }
                    // TODO: also split 'authorization' on commas as parameters?
                    else -> attr to emptyMap()
                }
            SipHeader(base, parameters)
        }

    return header to values
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
    val body = headers["content-length"]?.getOrNull(0)?.value?.toInt()?.let { this.readNBytes(it) }
    // TODO: parse body depending on content type (e.g. multipart)
    val firstLineSplit = firstLine.split(" ")
    when (firstLineSplit[0]) {
        // TODO: also check last element in line is SIP/2.0?
        "REGISTER" ->
            return SipRequest(
                method = SipMethod.REGISTER,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "SUBSCRIBE" ->
            return SipRequest(
                method = SipMethod.SUBSCRIBE,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "INVITE" ->
            return SipRequest(
                method = SipMethod.INVITE,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "ACK" ->
            return SipRequest(
                method = SipMethod.ACK,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "CANCEL" ->
            return SipRequest(
                method = SipMethod.CANCEL,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "BYE" ->
            return SipRequest(
                method = SipMethod.BYE,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "OPTIONS" ->
            return SipRequest(
                method = SipMethod.OPTIONS,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "MESSAGE" ->
            return SipRequest(
                method = SipMethod.MESSAGE,
                firstLineParam = firstLine,
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "SIP/2.0" -> {
            val code = firstLineSplit.getOrNull(1)?.toInt() ?: return null
            return SipResponse(
                statusCode = SipStatusCode(code),
                firstLineParam = firstLine,
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
