//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.telephony.Rlog
import android.telephony.TelephonyManager
import android.util.Base64

data class SipAkaResult(val res: ByteArray, val ck: ByteArray, val ik: ByteArray)

private const val TAG = "PHH SipChallenge"

fun sipAkaChallenge(tm: TelephonyManager, nonceB64: String): SipAkaResult {
    val nonce = Base64.decode(nonceB64, Base64.DEFAULT)

    val rand = nonce.take(16)
    val autn = nonce.drop(16).take(16)
    // val mac = nonce.drop(32)

    val challengeBytes = listOf(rand.size.toByte()) + rand + autn.size.toByte() + autn
    val challengeArray = challengeBytes.toByteArray()

    val challenge = Base64.encodeToString(challengeArray, Base64.NO_WRAP)
    Rlog.d(TAG, "Challenge B64 is $challenge")

    val responseB64 =
        tm.getIccAuthentication(
            TelephonyManager.APPTYPE_USIM,
            TelephonyManager.AUTHTYPE_EAP_AKA,
            challenge
        )
    val response = Base64.decode(responseB64, Base64.DEFAULT)
    if (response[0] != (0xdb).toByte()) {
        Rlog.d(TAG, "AKA challenge from SIP failed")
        throw Exception("AKA Challenge from SIP failed")
    }

    val responseStream = response.iterator()

    // 0xdb
    responseStream.nextByte()

    val resLen = responseStream.nextByte().toInt()
    Rlog.d(TAG, "resLen $resLen")
    val res = (0 until resLen).map { responseStream.nextByte() }.toList()

    val ckLen = responseStream.nextByte().toInt()
    Rlog.d(TAG, "ckLen $ckLen")
    val ck = (0 until ckLen).map { responseStream.nextByte() }.toList()

    val ikLen = responseStream.nextByte().toInt()
    Rlog.d(TAG, "ikLen $ikLen")
    val ik = (0 until ikLen).map { responseStream.nextByte() }.toList()

    Rlog.d(TAG, "Got res $res ck $ck ik $ik")

    return SipAkaResult(res = res.toByteArray(), ck = ck.toByteArray(), ik = ik.toByteArray())
}

data class SipAkaDigest(
    val user: String,
    val realm: String,
    val uri: String,
    val nonceB64: String,
    val opaque: String?,
    private val akaResult: SipAkaResult
) {
    var nonceCount: String = "0"
    var cnonce: String = ""
    private val H1 = ("$user:$realm:".toByteArray() + akaResult.res).toMD5()
    private val H2 = "REGISTER:$uri".toMD5()
    var digest: String = ""

    init {
        Rlog.d(TAG, "H1 = $H1, H2 = REGISTER:$uri = $H2")
        increment()
    }

    fun increment() {
        nonceCount = "%08d".format(nonceCount.toInt() + 1)
        cnonce = randomBytes(8).toHex() // 16 bytes on some traces
        digest = "$H1:$nonceB64:$nonceCount:$cnonce:auth:$H2".toMD5()
        Rlog.d(TAG, "chall $H1:$nonceB64:$nonceCount:$cnonce:auth:$H2 $digest")
    }

    override fun toString(): String =
        """Digest username="$user",realm="$realm",nonce="$nonceB64",uri="$uri",response="$digest",algorithm=AKAv1-MD5,cnonce="$cnonce",qop=auth,nc=$nonceCount""" +
            (if (opaque != null) ",opaque=$opaque" else "")
}
