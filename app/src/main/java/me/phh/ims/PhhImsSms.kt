//SPDX-License-Identifier: GPL-2.0
package me.phh.ims

import android.telephony.Rlog
import android.telephony.SmsManager
import android.telephony.ims.stub.ImsSmsImplBase
import me.phh.sip.SipHandler

// handle sms from device to ims
// frameworks/base/telephony/java/android/telephony/ims/stub/ImsSmsImplBase.java
class PhhImsSms(val slotId: Int) : ImsSmsImplBase() {
    companion object {
        private const val TAG = "Phh ImsSms"
    }

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
        try {
            // called when android tries to send a sms?
            Rlog.d(TAG, "$slotId sendSms $token, $messageRef, $format, $smsc")
            if (format != "3gpp") {
                // we only know how to send 3gpp formatted sms.
                // Android should do that correctly, error if not that will
                // properly display 'message not sent' in messaging app
                onSendSmsResultError(
                    token,
                    messageRef,
                    ImsSmsImplBase.SEND_STATUS_ERROR,
                    SmsManager.RESULT_INVALID_SMS_FORMAT,
                    RESULT_NO_NETWORK_ERROR
                )
                return
            }
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
                smsc,
                pdu,
                messageRef,
                {
                    // success cb
                    onSendSmsResultSuccess(token, messageRef)
                },
                {
                    // XXX better error code
                    onSendSmsResultError(
                        token,
                        messageRef,
                        ImsSmsImplBase.SEND_STATUS_ERROR,
                        SmsManager.RESULT_ERROR_GENERIC_FAILURE,
                        RESULT_NO_NETWORK_ERROR
                    )
                }
            )
        } catch(t: Throwable) {
            android.util.Log.e(TAG, "Failed sending sms", t)
        }
    }
    override fun acknowledgeSms(token: Int, messageRef: Int, result: Int) {
        // called when android acks a received sms
        Rlog.d(TAG, "$slotId acknowledgeSms $token, $messageRef, $result")

        // open notification on error?
        val error = result != ImsSmsImplBase.DELIVER_STATUS_OK
        sipHandler.sendSmsAck(token, messageRef, error)
    }
    override fun acknowledgeSmsReport(token: Int, messageRef: Int, result: Int) {
        // called when android acks onSmsStatusReportReceived?
        Rlog.d(TAG, "$slotId acknowledgeSmsReport $token, $messageRef, $result")
    }
    override fun onReady() {
        // should not do anything before this is called
        Rlog.d(TAG, "$slotId onReady")
    }
    // outside -> phone API
    // on message received from ims call onSmsReceived(token, format, pdu)
    // on sms successfully sent to ims call onSendSmsResultSuccess(token, messageRef)
    // on error onSendSmsResultError(token, messageRef, status, reason, networkErrorCode)
    // on status report of a send message is received call
    //      onSmsStatusReportReceived(token, format, pdu)

}
