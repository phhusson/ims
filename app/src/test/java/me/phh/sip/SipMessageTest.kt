package me.phh.sip

import org.junit.Test

val messageRequest = """
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
	Content-Length: 6
	""".trimIndent().replace("\n", "\r\n") + "\r\n\r\n" + String(byteArrayOf(2, 0, 0x41, 2, 0, 0))

val invalidRequest = """
	not a known request type
	Via: something
	""".trimIndent().replace("\n", "\r\n") + "\r\n\r\n"

val okResponse = """
	SIP/2.0 200 OK
	To: <sip:ssg-m-07-f0.smsc.imsnw.kddi.ne.jp>
	From: <sip:+818012341234@ims.mnc051.mcc440.3gppnetwork.org>;tag=fd387c84
	Call-ID: 8SYJMQy24xcFyJ7s-MXFag..@2001::1234
	Content-Length: 0
	""".trimIndent().replace("\n", "\r\n") + "\r\n\r\n"

class SipMessageTests { 
	@Test
	fun `parse single message request`() {
		val reader = messageRequest.toByteArray().inputStream().bufferedReader()
		val message = parseMessage(reader)
		require(message is SipRequest)
		require(message.method == SipMethod.MESSAGE)
		require(message.message.headers["cseq"]!![0].value == "1 MESSAGE")
	}

	@Test
	fun `parse invalid message fails`() {
		val reader = invalidRequest.toByteArray().inputStream().bufferedReader()
		val message = parseMessage(reader)
		require(message == null)
	}

	@Test
	fun `parse two messages in a stream`() {
		val reader = (messageRequest + okResponse).toByteArray().inputStream().bufferedReader()
		val message1 = parseMessage(reader)
		require(message1 is SipRequest)
		val message2 = parseMessage(reader)
		require(message2 is SipResponse)
		require(message2.statusCode == SipStatusCode(200))
	}
}
