package me.phh.sip

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
    NOTIFY,
}

typealias SipStatusCode = Int

typealias SipHeader = String

typealias SipHeadersMap = Map<String, List<SipHeader>>

@OptIn(ExperimentalStdlibApi::class)
abstract class SipMessage() {
    abstract val firstLine: String
    abstract val headers: SipHeadersMap
    abstract val body: ByteArray

    // serialize message for sending
    fun toByteArray(): ByteArray =
        this.headers
            .asSequence()
            .map {
                // regroup headers that don't like being split when sending
                (header, values) ->
                when (header) {
                    "allow",
                    "security-client",
                    "security-server",
                    "supported" -> header to listOf(values.joinToString(", "))
                    else -> header to values
                }
            }
            .fold(
                emptyList<String>(),
                { lines, (header, values) ->
                    lines +
                        values.map {
                            "${header.replaceFirstChar(Char::titlecase)}: ${it.toString()}"
                        }
                }
            )
            .map { it.toByteArray() }
            .plus(listOf(ByteArray(0), this.body))
            .fold(this.firstLine.toByteArray(), { msg, line -> msg + "\r\n".toByteArray() + line })
}

open class SipCommonMessage(
    override val firstLine: String,
    private val headersParam: SipHeadersMap,
    // TODO: messageBody needs to handle multipart, including nested multipart,
    // so needs to be a tree of sort? We can probably flatten it into
    // Map<String, List<ByteArray>> where first string is content type?
    // (second part list because there could be multiple of the same
    // and map doesn't allow duplicates)
    // See RFC5621 section 3
    override val body: ByteArray = ByteArray(0),
    private val autofill: Boolean = true,
) : SipMessage() {
    override val headers: SipHeadersMap
    init {
        headers = if (autofill) completeHeaders() else headersParam
    }

    override fun toString(): String =
        String(toByteArray(), Charsets.US_ASCII).replace("\r\n", "\n> ")

    private fun completeHeaders(): SipHeadersMap {
        /* some headers can be automatically generated:
         * - Content-Length (rfc3261 section 20.14)
         * - Call-ID if not already set
         * - 'branch' in 'Via' if not already set (rfc3261 section 20.42)
         * - Max-Forwards
         *
         * return map as mutable because request/response code piles up
         * a few more headersParam before casting it to unmutable
         */
        val newHeaders = mutableMapOf<String, List<SipHeader>>()
        if (headersParam["content-length"] == null) {
            newHeaders["content-length"] = listOf((this.body.size).toString())
        }
        if (headersParam["call-id"] == null) {
            newHeaders["call-id"] = listOf(randomBytes(12).toHex())
        }
        if (headersParam["max-forwards"] == null) {
            newHeaders["max-forwards"] = listOf("70")
        }
        if (headersParam["user-agent"] == null) {
            newHeaders["user-agent"] = listOf("phh ims 0.1")
        }
        val via = headersParam["via"]
        if (via != null) {
            newHeaders["via"] =
                via.map {
                    if (it.contains(";branch=")) {
                        it
                    } else {
                        "$it;branch=z9hG4bK${randomBytes(6).toHex()}"
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
    override val body: ByteArray = ByteArray(0),
    private val autofill: Boolean = true,
) : SipMessage() {
    private val message: SipCommonMessage
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

    override val firstLine = message.firstLine
    override val headers = message.headers
    override fun toString(): String = message.toString()

    private fun completeRequestHeaders(): SipHeadersMap {
        val newHeaders = mutableMapOf<String, List<SipHeader>>()

        if (headersParam["cseq"] == null) {
            newHeaders["cseq"] = listOf("1 ${this.method}")
        }

        val from = headersParam["from"]
        if (from != null) {
            newHeaders["from"] =
                from.map {
                    if (it.contains(";tag=")) {
                        it
                    } else {
                        "$it;tag=${randomBytes(6).toHex()}"
                    }
                }
        }

        return headersParam + newHeaders
    }
}

data class SipResponse(
    val statusCode: SipStatusCode,
    val statusString: String,
    private val headersParam: SipHeadersMap,
    override val body: ByteArray = ByteArray(0),
    private val autofill: Boolean = true,
) : SipMessage() {
    private val message: SipCommonMessage
    init {
        val headers = if (autofill) completeResponseHeaders() else headersParam

        message =
            SipCommonMessage(
                firstLine = "SIP/2.0 $statusCode $statusString",
                headersParam = headers,
                body = body,
                autofill = autofill,
            )
    }
    override val firstLine = message.firstLine
    override val headers = message.headers
    override fun toString(): String = message.toString()

    private fun completeResponseHeaders(): SipHeadersMap {
        val newHeaders = mutableMapOf<String, List<SipHeader>>()

        val to = headersParam["to"]
        if (to != null) {
            newHeaders["to"] =
                to.map {
                    if (it.contains(";tag=")) {
                        it
                    } else {
                        "$it;tag=${randomBytes(6).toHex()}"
                    }
                }
        }

        return headersParam + newHeaders
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
private val splitComma = "(<[^>]*>|[^,]+?)+".toRegex()

@OptIn(ExperimentalStdlibApi::class)
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
            "allow",
            "contact",
            "from",
            "p-asserted-identity",
            "security-client",
            "security-verify",
            "supported",
            "to" -> splitComma.findAll(valueRaw).toList().map { it.groupValues[0].trim() }
            else -> listOf(valueRaw)
        }

    return header to values
}

@OptIn(ExperimentalStdlibApi::class)
private fun splitParams(
    value: String,
    splitRegex: Regex,
    paramRegex: Regex,
    lowercase: Boolean
): Pair<String, Map<String, String?>> {
    val paramSplit = splitRegex.findAll(value).toList().map { it.groupValues[0].trim() }
    return paramSplit[0] to
        paramSplit
            .slice(1..paramSplit.size - 1)
            .map Map@{
                val (a, b) = paramRegex.find(it)?.destructured ?: return@Map it.lowercase() to null
                a.lowercase() to (if (lowercase) b.lowercase() else b)
            }
            .toMap()
}

/* split parameters by semicolum.
 * Note semi-column can be present in <sip:> tokens and we should not
 * split these, hence the regex.
 * both parameter name and its value are case insensitive, so lowercased.
 * */
private val splitParam = "(<[^>]*>|[^;]+?)+".toRegex()
private val splitParamValue = "^([^=]+)=?(.*)".toRegex()

fun SipHeader.getParams(): Pair<String, Map<String, String?>> =
    splitParams(this, splitParam, splitParamValue, true)

/* split www-authenticate header
 * the first separator is a space then comma separates but we just assume
 * words contain no space unless quoted
 * quotes are removed from value, which is case sensitive
 */
private val splitAuth = """("[^"]*"|[^ ,]+?)+""".toRegex()
private val splitAuthValue = """^([^=]+)="?([^"]*)"?""".toRegex()

fun SipHeader.getAuthValues(): Pair<String, Map<String, String?>> =
    splitParams(this, splitAuth, splitAuthValue, false)

fun parseHeaders(sequence: Sequence<String>): SipHeadersMap =
    sequence.fold(
        emptyMap<String, List<SipHeader>>(),
        fold@{ headers, line ->
            val (header, value) = sipHeaderOf(line) ?: return@fold headers
            val oldVal = headers.get(header) ?: emptyList<SipHeader>()

            headers + (header to oldVal + value)
        }
    )

fun String.toSipHeadersMap(): SipHeadersMap = parseHeaders(this.lines().asSequence())

fun SipReader.parseHeaders(): SipHeadersMap = parseHeaders(this.lineSequence())

fun SipReader.parseMessage(): SipMessage? {
    val firstLine = this.readLine() ?: return null
    val headers = this.parseHeaders()
    val body =
        headers["content-length"]?.getOrNull(0)?.toInt()?.let { this.readNBytes2(it) }
            ?: ByteArray(0)
    // TODO: parse body depending on content type (e.g. multipart)
    val firstLineSplit = firstLine.split(" ")
    when (firstLineSplit[0]) {
        // TODO: also check last element in line is SIP/2.0?
        "REGISTER",
        "SUBSCRIBE",
        "INVITE",
        "ACK",
        "CANCEL",
        "BYE",
        "OPTIONS",
        "MESSAGE",
        "NOTIFY" ->
            return SipRequest(
                method = SipMethod.valueOf(firstLineSplit[0]),
                destination = firstLineSplit[1],
                headersParam = headers,
                body = body,
                autofill = false,
            )
        "SIP/2.0" -> {
            val code = firstLineSplit.getOrNull(1)?.toInt() ?: return null
            return SipResponse(
                statusCode = code,
                statusString = firstLineSplit.slice(2..firstLineSplit.size - 1).joinToString(" "),
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
