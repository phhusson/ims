package me.phh.ims

import android.telephony.Rlog
import android.telephony.SmsManager
import android.telephony.ims.stub.ImsSmsImplBase
import me.phh.sip.SipHandler

// handle sms from device to ims
// frameworks/base/telephony/java/android/telephony/ims/stub/ImsSmsImplBase.java
class PhhImsSms(val slotId: Int) : ImsSmsImplBase() {
    lateinit var sipHandler: SipHandler

    // phone -> outside API
    override fun sendSms(
        token: Int,
        messageRef: Int,
        format: String?,
        smsc: String?,
        isRetry: Boolean,
        pdu: ByteArray
    ) {
        val content = String(pdu)
        // called when android tries to send a sms?
        Rlog.d("PHH", "ImsSms $slotId sendSms $token, $messageRef, $format, $smsc, $content")
        if (::sipHandler.isInitialized == false) {
            onSendSmsResultError(
                token,
                messageRef,
                ImsSmsImplBase.SEND_STATUS_ERROR_RETRY,
                SmsManager.RESULT_ERROR_NO_SERVICE,
                RESULT_NO_NETWORK_ERROR
            )
            return
        }
        sipHandler.sendSms(
            pdu,
            {
                // success cb
                onSendSmsResultSuccess(token, messageRef)
            },
            {
                // XXX better error code
                onSendSmsResultError(
                    token,
                    messageRef,
                    ImsSmsImplBase.SEND_STATUS_ERROR_RETRY,
                    SmsManager.RESULT_ERROR_GENERIC_FAILURE,
                    RESULT_NO_NETWORK_ERROR
                )
            }
        )
    }
    override fun acknowledgeSms(token: Int, messageRef: Int, result: Int) {
        // called when android acks a received sms?
        Rlog.d("PHH", "ImsSms $slotId acknowledgeSms $token, $messageRef, $result")
    }
    override fun acknowledgeSmsReport(token: Int, messageRef: Int, result: Int) {
        // called when android acks onSmsStatusReportReceived?
        Rlog.d("PHH", "ImsSms $slotId acknowledgeSmsReport $token, $messageRef, $result")
    }
    override fun onReady() {
        // should not do anything before this is called
        Rlog.d("PHH", "ImsSms $slotId onReady")
    }
    // outside -> phone API
    // on message received from ims call onSmsReceived(token, format, pdu)
    // on sms successfully sent to ims call onSendSmsResultSuccess(token, messageRef)
    // on error onSendSmsResultError(token, messageRef, status, reason, networkErrorCode)
    // on status report of a send message is received call
    //      onSmsStatusReportReceived(token, format, pdu)

}
