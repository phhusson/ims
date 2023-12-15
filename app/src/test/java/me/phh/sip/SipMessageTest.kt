//SPDX-License-Identifier: GPL-2.0
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
    k:path,   gruu,sec-agree
    User-Agent: ims phh v0.1
    Security-Verify: invalid, ipsec-3gpp;q=0.5;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=null;spi-c=52340051;spi-s=3859;port-c=7807;port-s=7777, invalid2;q=0.9, ipsec-3gpp;q=0.6;alg=hmac-md5-96;prot=esp;mod=trans;ealg=aes-cbc;spi-c=52340051;spi-s=3859;port-c=7807;port-s=7777, ipsec-3gpp;q=0.7;alg=notsupported;prot=esp;mod=trans;ealg=aes-cbc;spi-c=52340051;spi-s=3859;port-c=7807;port-s=7777,
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
        val headers = message.headers
        require(headers["cseq"]!![0] == "1 MESSAGE")
        require(headers["supported"] == listOf("path", "gruu", "sec-agree"))
        val (fromVal, fromParams) = headers["from"]!![0].getParams()
        require(fromVal == "<sip:+818012341234@ims.mnc051.mcc440.3gppnetwork.org>")
        require(fromParams == mapOf("tag" to "fd387c84"))
        val supported_alg = listOf("hmac-md5-96", "hmac-sha-1-96")
        val (svValue, svParams) =
            headers["security-verify"]!!
                .map { it.getParams() }
                .filter { supported_alg.contains(it.component2()["alg"]) }
                .sortedByDescending { it.component2()["q"]?.toFloat() ?: 0.toFloat() }[0]
        require(svValue == "ipsec-3gpp")
        require(svParams["prot"] == "esp")
        require(svParams["alg"] == "hmac-md5-96")
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
        require(message2.statusCode == 200)
    }

    @Test
    fun `serializating and parsing again yields identical object`() {
        val reader = messageRequest.inputStream().sipReader()

        val message = reader.parseMessage()
        require(message is SipRequest)
        val serialize = message.toByteArray()
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
        require(message2.firstLine == message.firstLine)
        require(message2.headers["from"] == message.headers["from"])
        require(message2.headers["to"] == message.headers["to"])
        require(message2.headers["route"] == message.headers["route"])
        require(message2.headers["call-id"] == message.headers["call-id"])
        require(message2.headers["content-length"] == message.headers["content-length"])
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

    @Test
    fun `check autofill adds missing headers`() {
        val headers = """
            From: test
            Via: test
        """.toSipHeadersMap()
        val message =
            SipRequest(
                method = SipMethod.REGISTER,
                destination = "xxx",
                headersParam = headers,
            )
        require(message.firstLine == "REGISTER xxx SIP/2.0")
        require(message.headers["cseq"] == listOf("1 REGISTER"))
        require(message.headers["from"]!![0].contains(";tag="))
        require(message.headers["via"]!![0].getParams().component2()["branch"] != null)
    }

    @Test
    fun `check autofill does not replace headers`() {
        val headers =
            """
            From: test;tag=foo
            Via: test;branch=123
            CSeq: 123 test
        """.toSipHeadersMap()
        val message =
            SipRequest(
                method = SipMethod.REGISTER,
                destination = "xxx",
                headersParam = headers,
            )
        require(message.headers["cseq"] == listOf("123 test"))
        require(message.headers["from"]!![0].contains(";tag=foo"))
        require(message.headers["via"]!![0].getParams().component2()["branch"] == "123")
    }

    @Test
    fun `check auth values splitting`() {
        val header =
            """Digest realm="ims.mnc051.mcc440.3gppnetwork.org",nonce="8QBO8ceNHcoud1KsnG5hknEPHYM2vQAAERNXvVk6N5M=",algorithm=AKAv1-MD5,qop="auth""""
        val (type, params) = header.getAuthValues()
        require(type == "Digest")
        require(params["qop"]!! == "auth")
        require(params["algorithm"]!! == "AKAv1-MD5")
    }

    @Test
    fun `check serialization regroups allow`() {
        val headers =
            """
            Allow: one, two
            Allow: three
        """.toSipHeadersMap()
        val message =
            SipRequest(
                method = SipMethod.REGISTER,
                destination = "xxx",
                headersParam = headers,
                autofill = false
            )
        require(
            String(message.toByteArray()) ==
                "REGISTER xxx SIP/2.0\r\nAllow: one, two, three\r\n\r\n"
        )
        require(message.toString() == "REGISTER xxx SIP/2.0\n> Allow: one, two, three\n> \n> ")
    }

    @Test
    fun `check header manipulation`() {
        var headers =
            """
            From: test
            Route: route1
        """.toSipHeadersMap()
        require(headers["route"] == listOf("route1"))

        headers -= "route"
        require("route" !in headers)

        headers += ("route" to listOf("route2"))
        require(headers["route"] == listOf("route2"))
    }
}
