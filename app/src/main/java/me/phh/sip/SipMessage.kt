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
    MESSAGE
}

data class SipStatusCode(val code: Int)

data class SipHeader(val value: String, val parameters: Map<String, String>)

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
) : SipMessage()

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
 *  - some headers have parameters split by ;, thanksfully no comma separated list
 *    has these so there is no ambiguity vs. how they'd distribute in this case...
 *  - headers and parameters are case-insensitive
 */
private val splitHeader = "^(.+?) *: *(.+)$".toRegex()

fun SipReader.parseHeaders(): Map<String, List<SipHeader>> =
    this.lineSequence()
        .fold(
            emptyMap<String, List<SipHeader>>(),
            fold@{ headers, line ->
                // ignore anything we don't recognize
                val (headerRaw, value) = splitHeader.find(line)?.destructured ?: return@fold headers
                val header = headerRaw.lowercase()
                val oldVal = headers.get(header) ?: emptyList<SipHeader>()
                // TODO: split value for comma separated headers
                // TODO: split parameters from value, making sure not to break <sip:...;...> apart
                headers.plus(header to oldVal.plus(SipHeader(value, emptyMap())))
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

fun SipCommonMessage.serialize(): ByteArray =
    // TODO: generate content-length header from body.size ?
    this.headers
        .asSequence()
        .fold(
            emptyList<String>(),
            { lines, (header, values) ->
                // TODO: handle parameters
                lines + values.map { "%s: %s".format(header, it.value) }
            }
        )
        .map { it.toByteArray() }
        .plus(listOf(ByteArray(0), this.body ?: ByteArray(0)))
        .fold(this.firstLine.toByteArray(), { msg, line -> msg + "\r\n".toByteArray() + line })
