//SPDX-License-Identifier: GPL-2.0
package me.phh.ims

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Binder
import android.os.SystemClock
import android.telephony.Rlog
import android.telephony.ims.ImsService
import android.telephony.ims.feature.MmTelFeature
import android.telephony.ims.feature.RcsFeature
import android.telephony.ims.stub.ImsConfigImplBase
import android.telephony.ims.stub.ImsRegistrationImplBase
import android.telephony.imsmedia.ImsMediaManager

class PhhImsService : ImsService() {
    companion object {
        private const val TAG = "PHH ImsService"
        var instance: PhhImsService? = null
    }

    val receiver: PhhImsBroadcastReceiver = PhhImsBroadcastReceiver()

    override fun onCreate() {
        Rlog.d(TAG, "onCreate")

        val intentFilter = IntentFilter()
        intentFilter.addAction(receiver.ALARM_PERIODIC_REGISTER)
        this.registerReceiver(receiver, intentFilter, Context.RECEIVER_NOT_EXPORTED)

        this.armPeriodicRegisterAlarm()
    }
    fun armPeriodicRegisterAlarm() {
        val alarmManager = this.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val intent = Intent(receiver.ALARM_PERIODIC_REGISTER)
        val pendingIntent =
            PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
        // We want recurring 3000s but recurring alarms don't wake up from
        // doze: alarm will re-arm itself.
        alarmManager.setAndAllowWhileIdle(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + 3_000_000,
            pendingIntent
        )
        Rlog.d(TAG, "Alarm set")
    }

    // XXX one per slot id...
    var mmTelFeature: PhhMmTelFeature? = null
    override fun createMmTelFeature(slotId: Int): MmTelFeature {
        Rlog.d(TAG, "createMmTelFeature")
        var feature = mmTelFeature
        if (feature == null) {
            feature = PhhMmTelFeature(slotId)
            mmTelFeature = feature
        }
        return feature
    }
    override fun createRcsFeature(slotId: Int): RcsFeature? {
        Rlog.d(TAG, "createRcsFeature")
        return null
    }

    val config = PhhImsConfig()

    override fun getConfig(slotId: Int): ImsConfigImplBase {
        Rlog.d(TAG, "getConfig")
        return config
    }

    class LocalBinder : Binder() {
        fun getService(): PhhImsService {
            Rlog.d(TAG, "LocalBinder getService")
            return PhhImsService()
        }
    }

    // XXX cache one per slot id
    val imsRegistration = ImsRegistrationImplBase()
    override fun getRegistration(slotId: Int): ImsRegistrationImplBase {
        Rlog.d(TAG, "getRegistration $slotId")
        return imsRegistration
    }

    override fun onDestroy() {
        Rlog.d(TAG, "onDestroy")
        instance = null
    }

    override fun readyForFeatureCreation() {
        Rlog.d(TAG, "readyForFeatureCreation")
        if (instance != null && instance !== this) {
            throw RuntimeException()
        }
        instance = this
    }
}
