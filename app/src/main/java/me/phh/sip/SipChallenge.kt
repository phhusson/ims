package me.phh.ims

import android.telephony.TelephonyManager
import android.util.Base64
import android.util.Log

data class AkaResult(val res: ByteArray, val ck: ByteArray, val ik: ByteArray)

fun sipAkaChallenge(tm: TelephonyManager, nonceB64: String): AkaResult {
    val nonce = Base64.decode(nonceB64, Base64.DEFAULT)

    val rand = nonce.take(16)
    val autn = nonce.drop(16).take(16)
    // val mac = nonce.drop(32)

    val challengeBytes = listOf(rand.size.toByte()) + rand + autn.size.toByte() + autn
    val challengeArray = challengeBytes.toByteArray()

    val challenge = Base64.encodeToString(challengeArray, Base64.NO_WRAP)
    Log.d("PHH", "Challenge B64 is $challenge")

    val responseB64 =
        tm.getIccAuthentication(
            TelephonyManager.APPTYPE_USIM,
            TelephonyManager.AUTHTYPE_EAP_AKA,
            challenge
        )
    val response = Base64.decode(responseB64, Base64.DEFAULT)
    if (response[0] != (0xdb).toByte()) {
        Log.d("PHH", "AKA challenge from SIP failed")
        throw Exception("AKA Challenge from SIP failed")
    }

    val responseStream = response.iterator()

    // 0xdb
    responseStream.nextByte()

    val resLen = responseStream.nextByte().toInt()
    Log.d("PHH", "resLen $resLen")
    val res = (0 until resLen).map { responseStream.nextByte() }.toList()

    val ckLen = responseStream.nextByte().toInt()
    Log.d("PHH", "ckLen $ckLen")
    val ck = (0 until ckLen).map { responseStream.nextByte() }.toList()

    val ikLen = responseStream.nextByte().toInt()
    Log.d("PHH", "ikLen $ikLen")
    val ik = (0 until ikLen).map { responseStream.nextByte() }.toList()

    Log.d("PHH", "Got res $res ck $ck ik $ik")

    return AkaResult(res = res.toByteArray(), ck = ck.toByteArray(), ik = ik.toByteArray())
}

data class AkaDigest(
    val user: String,
    val realm: String,
    val uri: String,
    val nonceB64: String,
    val opaque: String?,
    private val akaResult: AkaResult
) {
    var nonceCount: String = "0"
    var cnonce: String = ""
    private val H1 = ("$user:$realm:".toByteArray() + akaResult.res).toMD5()
    private val H2 = "REGISTER:$uri".toMD5()
    var digest: String = ""

    init {
        Log.d("PHH", "H1 = $H1, H2 = REGISTER:$uri = $H2")
        increment()
    }

    fun increment() {
        nonceCount = "%08d".format(nonceCount.toInt() + 1)
        cnonce = randomBytes(8).toHex()
        digest = "$H1:$nonceB64:$nonceCount:$cnonce:auth:$H2".toMD5()
        Log.d("PHH", "chall $H1:$nonceB64:$nonceCount:$cnonce:auth:$H2 $digest")
    }

    override fun toString(): String =
        """Digest username="$user",realm="$realm",nonce="$nonceB64",uri="$uri",response="$digest",algorithm=AKAv1-MD5,cnonce="$cnonce",qop=auth,nc=$nonceCount""" +
            (if (opaque != null) ",opaque=$opaque" else "")
}
