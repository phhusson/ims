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



sealed class SipMessage()

data class SipCommonMessage(
    val firstLine: String,
    val headers: Map<String, List<SipHeader>>,
    // TODO: messageBody needs to handle multipart, including nested multipart,
    // so needs to be a tree of sort? We can probably flatten it into
    // Map<String, List<ByteArray>> where first string is content type?
    // (second part list because there could be multiple of the same
    // and map doesn't allow duplicates)
    // See RFC5621 section 3
    val body: ByteArray?,
) : SipMessage() {
    fun toByteArray(): ByteArray =
        // TODO: generate content-length header from body.size ?
        this.headers
            .asSequence()
            .fold(
                emptyList<String>(),
                { lines, (header, values) ->
                    lines + values.map { "$header: ${it.toString()}" }
                }
            )
            .map { it.toByteArray() }
            .plus(listOf(ByteArray(0), this.body ?: ByteArray(0)))
            .fold(this.firstLine.toByteArray(), { msg, line -> msg + "\r\n".toByteArray() + line })
}

data class SipRequest(
    val method: SipMethod,
    val message: SipCommonMessage,
) : SipMessage()

data class SipResponse(
    val statusCode: SipStatusCode,
    val message: SipCommonMessage,
) : SipMessage()

/* rfc3261 section 7 describes how headers should be formed, in particular:
 *  - spaces around : are ignored
 *  - multilines headers are allowed, continuation lines start with a space or tab
 *    and should be joined with a single space
 *  - some headers are comma separated lists, multiple occurence of these headers
 *    is identical to having separated values on single line
 *  - some headers have parameters split by ;
 *  - headers and parameters are case-insensitive
 */
private val splitHeader = "^([^:]+)\\s*:\\s*(.+)$".toRegex()
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


fun SipReader.parseHeaders(): Map<String, List<SipHeader>> =
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
    val commonMessage = SipCommonMessage(firstLine = firstLine, headers = headers, body = body)
    val firstLineSplit = firstLine.split(" ")
    when (firstLineSplit[0]) {
        // TODO: also check last element in line is SIP/2.0?
        "REGISTER" -> return SipRequest(method = SipMethod.REGISTER, message = commonMessage)
        "SUBSCRIBE" -> return SipRequest(method = SipMethod.SUBSCRIBE, message = commonMessage)
        "INVITE" -> return SipRequest(method = SipMethod.INVITE, message = commonMessage)
        "ACK" -> return SipRequest(method = SipMethod.ACK, message = commonMessage)
        "CANCEL" -> return SipRequest(method = SipMethod.CANCEL, message = commonMessage)
        "BYE" -> return SipRequest(method = SipMethod.BYE, message = commonMessage)
        "OPTIONS" -> return SipRequest(method = SipMethod.OPTIONS, message = commonMessage)
        "MESSAGE" -> return SipRequest(method = SipMethod.MESSAGE, message = commonMessage)
        "SIP/2.0" -> {
            val code = firstLineSplit.getOrNull(1)?.toInt() ?: return null
            return SipResponse(statusCode = SipStatusCode(code), message = commonMessage)
        }
        else -> return commonMessage
    }
}

