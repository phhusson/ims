//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.telephony.PhoneNumberUtils
import android.telephony.Rlog
import java.nio.ByteBuffer
import java.nio.ByteOrder

/* Helpers for GSM A Interface RP - SMS GSM layer 3
 *
 * Based on:
 *
 * https://www.etsi.org/deliver/etsi_ts/124000_124099/124011/15.03.00_60/ts_124011v150300p.pdf
 *
 * ... and a salt of wireshark's GPL-2.0-or-later
 * epan/dissectors/packet-gsm_a_rp.c
 */

private const val TAG = "PHH SipSms"

enum class SmsType(val value: Byte) {
    RP_DATA_TO_NETWORK(0),
    RP_DATA_FROM_NETWORK(1),
    RP_ACK_TO_NETWORK(2),
    RP_ACK_FROM_NETWORK(3),
    RP_ERROR_TO_NETWORK(4),
    RP_ERROR_FROM_NETWORK(5),
    RP_SNMA_TO_NETWORK(6),
}

data class SipSms(
    val type: SmsType,
    val ref: Byte,
    val pdu: ByteArray?,
)

// catch java.nio.BufferUnderflowException if buffer too small
fun ByteArray.SipSmsDecode(): SipSms? {
    var buf = ByteBuffer.wrap(this).order(ByteOrder.BIG_ENDIAN)

    val type = buf.get()
    when (type) {
        SmsType.RP_DATA_FROM_NETWORK.value -> {
            // ref needs to be used in ACK
            val ref = buf.get()

            val origAddrLen = buf.get().toInt()
            val origAddrBuf = ByteArray(origAddrLen)
            val origAddr =
                if (origAddrLen == 0) {
                    "unknown"
                } else {
                    buf.get(origAddrBuf, 0, origAddrLen)
                    // check if should use EF_ADN type instead
                    PhoneNumberUtils.calledPartyBCDToString(
                        origAddrBuf,
                        0,
                        origAddrLen,
                        PhoneNumberUtils.BCD_EXTENDED_TYPE_CALLED_PARTY
                    )
                }

            val destAddrLen = buf.get().toInt()
            val destAddr =
                if (destAddrLen == 0) {
                    "unknown"
                } else {
                    val destAddrBuf = ByteArray(destAddrLen)
                    buf.get(destAddrBuf, 0, destAddrLen)
                    // check if should use EF_ADN type instead
                    PhoneNumberUtils.calledPartyBCDToString(
                        destAddrBuf,
                        0,
                        destAddrLen,
                        PhoneNumberUtils.BCD_EXTENDED_TYPE_CALLED_PARTY
                    )
                }

            // signed bytes cast to int can be negative...
            val pduLen = buf.get().toUByte().toInt()
            Rlog.d(TAG, "SMS from $destAddr to $origAddr, pduLen $pduLen")
            val pdu = ByteArray(1 + origAddrLen + pduLen)
            pdu[0] = origAddrLen.toByte()
            origAddrBuf.copyInto(pdu, 1)
            buf.get(pdu, 1 + origAddrLen, pduLen)
            return SipSms(SmsType.RP_DATA_FROM_NETWORK, ref, pdu)
        }
        SmsType.RP_ACK_FROM_NETWORK.value -> {
            val ref = buf.get()

            /* "optional TLV" here -- we're not doing anything with it,
             * so ignore. Should look like this?
            val pduId = buf.get() -- id should always be 0x41
            val pduLen = buf.get().toInt()
            val pdu = ByteArray(pduLen)
            buf.get(pdu, 0, pduLen)
            */

            return SipSms(SmsType.RP_ACK_FROM_NETWORK, ref, null)
        }
        // RP_ERROR_FROM_NETWORK possible
        else -> {
            Rlog.w(TAG, "Got unhandled SMS pdu of type ${type}")
            return null
        }
    }
}

fun SipSmsEncodeSms(ref: Byte, smsc: String?, pdu: ByteArray): ByteArray {
    /* get smsc BCD representation first to compute encoded length */
    val smscBcd =
        if (smsc == null) {
            ByteArray(0)
        } else {
            PhoneNumberUtils.numberToCalledPartyBCD(
                smsc,
                PhoneNumberUtils.BCD_EXTENDED_TYPE_CALLED_PARTY
            )
        }
    /* constant overhead: rp type, ref, orig/dest/buf lengths */
    val bufLen = 5 + smscBcd.size + pdu.size
    val bufArray = ByteArray(bufLen)
    val buf = ByteBuffer.wrap(bufArray).order(ByteOrder.BIG_ENDIAN)

    buf.put(SmsType.RP_DATA_TO_NETWORK.value)
    buf.put(ref)

    // orig addr, can apparently keep it empty?
    buf.put(0)

    // dest addr, apparently smsc
    buf.put(smscBcd.size.toByte())
    buf.put(smscBcd)

    // original pdu
    buf.put(pdu.size.toByte())
    buf.put(pdu)
    return bufArray
}

fun SipSmsEncodeAck(ref: Byte): ByteArray {
    val bufArray = ByteArray(6)
    val buf = ByteBuffer.wrap(bufArray).order(ByteOrder.BIG_ENDIAN)

    buf.put(SmsType.RP_ACK_TO_NETWORK.value)
    buf.put(ref)

    // empty delivery report
    buf.put(0x41) // type delivery
    buf.put(2) // length
    buf.put(0)
    buf.put(0)

    return bufArray
}
