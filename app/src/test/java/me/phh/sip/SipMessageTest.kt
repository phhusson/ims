package me.phh.sip

import org.junit.Test

val binaryBody = (0..255).toList().map { it.toByte() }.toByteArray()

val messageRequest =
    ("""
    MESSAGE sip:ssg-m-07-f0.smsc.imsnw.kddi.ne.jp SIP/2.0
    Via: SIP/2.0/UDP [2001::1234]:6100;branch=z9hG4bK-557227-1---3c7feb1aa803b932;rport;transport=UDP
    Max-Forwards: 70
    Route: <sip:[2001:1234::a]:7777;lr>
    Route: <sip:[2001:1234::A]:7777;transport=udp;lr>
    Proxy-Require: sec-agree
    Require: sec-agree
    To: <sip:ssg-m-07-f0.smsc.imsnw.kddi.ne.jp>
    From: <sip:+818012341234@ims.mnc051.mcc440.3gppnetwork.org>;tag=fd387c84
    Call-ID: 8SYJMQy24xcFyJ7s-MXFag..@2001::1234
    CSeq: 1 MESSAGE
    Allow: MESSAGE
    Content-Type: application/vnd.3gpp.sms
    In-Reply-To: 4ee646d0-6274eee0@[2001:1234:1234:0000:0000:0000:0000:000d]
    Supported: path, gruu, sec-agree
    User-Agent: ims phh v0.1
    Security-Verify: ipsec-3gpp;q=0.5;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=null;spi-c=52340051;spi-s=3859;port-c=7807;port-s=7777
    Request-Disposition: no-fork
    P-Preferred-Identity: <sip:+818012341234@ims.mnc051.mcc440.3gppnetwork.org>
    Accept-Contact: *;+g.3gpp.smsip
    P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4405112341234123
    Content-Length: ${binaryBody.size}
    """
            .trimIndent()
            .replace("\n", "\r\n") + "\r\n\r\n")
        .toByteArray() + binaryBody

val invalidRequest =
    ("""
    not a known request type
    Via: something
    """
            .trimIndent()
            .replace("\n", "\r\n") + "\r\n\r\n")
        .toByteArray()

val okResponse =
    ("""
    SIP/2.0 200 OK
    To: <sip:ssg-m-07-f0.smsc.imsnw.kddi.ne.jp>
    From: <sip:+818012341234@ims.mnc051.mcc440.3gppnetwork.org>;tag=fd387c84
    Call-ID: 8SYJMQy24xcFyJ7s-MXFag..@2001::1234
    Content-Length: 0
    """
            .trimIndent()
            .replace("\n", "\r\n") + "\r\n\r\n")
        .toByteArray()

val emptyMessage = ByteArray(0)
val keepaliveMessage = "\r\n".toByteArray()

class SipMessageTests {
    @Test
    fun `parse single message request`() {
        val reader = messageRequest.inputStream().sipReader()

        val message = reader.parseMessage()
        require(message is SipRequest)
        require(message.method == SipMethod.MESSAGE)
        val headers = message.message.headers
        require(headers["cseq"]!![0].value == "1 MESSAGE")
        require(headers["supported"] == listOf("path", "gruu", "sec-agree").map { SipHeader(it, emptyMap()) } )
        require(headers["from"]!![0].value == "<sip:+818012341234@ims.mnc051.mcc440.3gppnetwork.org>")
        require(headers["from"]!![0].parameters == mapOf("tag" to "fd387c84"))
        require(headers["security-verify"]!![0].value == "ipsec-3gpp")
        require(headers["security-verify"]!![0].parameters["prot"] == "esp")
    }

    @Test
    fun `parse invalid message fails`() {
        val reader = invalidRequest.inputStream().sipReader()

        val message = reader.parseMessage()
        require(message is SipCommonMessage)
        require(message.firstLine == "not a known request type")
    }

    @Test
    fun `parse two messages in a stream`() {
        val reader = (messageRequest + okResponse).inputStream().sipReader()

        val message1 = reader.parseMessage()
        require(message1 is SipRequest)

        val message2 = reader.parseMessage()
        require(message2 is SipResponse)
        require(message2.statusCode == SipStatusCode(200))
    }

    @Test
    fun `serializating and parsing again yields identical object`() {
        val reader = messageRequest.inputStream().sipReader()

        val message = reader.parseMessage()
        require(message is SipRequest)
        val serialize = message.message.toByteArray()
        // can't compare full string as we lowercased headers, check start/end
        val firstLineEnd = messageRequest.indexOf('\n'.code.toByte()) + 1
        require(serialize.take(firstLineEnd) == messageRequest.take(firstLineEnd))
        require(
            serialize.takeLast(binaryBody.size + 4) == messageRequest.takeLast(binaryBody.size + 4)
        )

        val reader2 = serialize.inputStream().sipReader()
        val message2 = reader2.parseMessage()
        require(message2 is SipRequest)
        // SipCommonMessage includes byte arrays which are not directly comparable,
        // so we can't just require(message == message2). Check a few field manually instead.
        require(message2.method == message.method)
        require(message2.message.firstLine == message.message.firstLine)
        require(message2.message.headers["from"] == message.message.headers["from"])
        require(message2.message.headers["to"] == message.message.headers["to"])
        require(message2.message.headers["route"] == message.message.headers["route"])
        require(message2.message.headers["call-id"] == message.message.headers["call-id"])
        require(
            message2.message.headers["content-length"] == message.message.headers["content-length"]
        )
    }

    @Test
    fun `try to parse empty message`() {
        val reader = emptyMessage.inputStream().sipReader()

        val message = reader.parseMessage()
        require(message == null)
    }

    @Test
    fun `try to parse keepalive crlf message`() {
        val reader = keepaliveMessage.inputStream().sipReader()

        val message = reader.parseMessage()
        require(message == null)
    }

    @Test
    fun `try to parse crlf then message`() {
        val reader = (keepaliveMessage + messageRequest).inputStream().sipReader()

        val message = reader.parseMessage()
        require(message == null)

        val message2 = reader.parseMessage()
        require(message2 is SipRequest)
    }
}
