package me.phh.sip

import java.io.BufferedReader

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

fun parseHeaders(input: BufferedReader): Map<String, List<SipHeader>> =
    input
        .lineSequence()
        .takeWhile { it.isNotBlank() }
        .fold(
            emptyMap<String, List<SipHeader>>(),
            fold@{ headers, line ->
                // ignore anything we don't recognize
                // TODO: if line starts with a space, content should be happened to previous value
                // with newline and leading spaces being replaced by a single space
                val (headerRaw, value) = splitHeader.find(line)?.destructured ?: return@fold headers
                val header = headerRaw.lowercase()
                val oldVal = headers.get(header) ?: emptyList<SipHeader>()
                // TODO: split value for comma separated headers
                // TODO: split parameters from value, making sure not to break <sip:...;...> apart
                headers.plus(header to oldVal.plus(SipHeader(value, emptyMap())))
            }
        )

fun parseMessage(input: BufferedReader): SipMessage? {
    val firstLine = input.readLine() ?: return null
    val headers = parseHeaders(input)
    val body = headers["content-length"]?.getOrNull(0)?.value?.toInt()?.let(::ByteArray)
    // XXX BROKEN ... and now we're here, there's no way to read into a ByteArray from a
    // BufferedReader,
    // so we need to start over with another reader type?
    // We could:
    //  - read into a char array, convert to string and back to bytearray... ugh.
    //    Is there a charset that'd be safe to use for this? sms in particular are sent as
    //    binary so we need something that doesn't mangle anything.
    //  - reimplement a buffered-reader-like API over InputStream which deals with bytes
    //  - give up on pretty functional parsing and implement a state maching that just matches
    //    for expected patterns at each point of the parsing
    //  - implement an ANTLR grammar for SIP? But I'm not sure it's a good fit, and couldn't
    //    find anyone doing this for e.g. HTTP headers so it's probably not a good solution
    body?.let { input.skip(it.size.toLong()) }
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

fun serializeMessage(message: SipCommonMessage): ByteArray =
    // TODO: generate content-length header from body.size ?
    message.headers
        .asSequence()
        .fold(
            emptyList<String>(),
            { lines, (header, values) ->
                // TODO: handle parameters
                lines + values.map { "%s: %s".format(header, it.value) }
            }
        )
        .map { it.toByteArray() }
        .plus(listOf(ByteArray(0), message.body ?: ByteArray(0)))
        .fold(message.firstLine.toByteArray(), { msg, line -> msg + "\r\n".toByteArray() + line })
