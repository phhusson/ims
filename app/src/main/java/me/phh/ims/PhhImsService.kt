package me.phh.ims

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.telephony.Rlog
import android.telephony.ims.ImsService
import android.telephony.ims.feature.MmTelFeature
import android.telephony.ims.feature.RcsFeature
import android.telephony.ims.stub.ImsConfigImplBase
import android.telephony.ims.stub.ImsRegistrationImplBase

class PhhImsBroadcastReceiver : BroadcastReceiver() {
    companion object {
        val TAG = "Phh ImsBroadcastReceiver"
    }

    
    }
}

class PhhImsService : ImsService() {
    companion object {
        val TAG = "PHH ImsService"
        var instance: PhhImsService? = null
    }

    
    }

    // XXX one per slot id...
    var mmTelFeature: PhhMmTelFeature? = null
    override fun createMmTelFeature(slotId: Int): MmTelFeature {
        Rlog.d(TAG, "createMmTelFeature")
        var feature = mmTelFeature
        if (feature == user) {
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

    val receiver: PhhImsBroadcastReceiver = PhhImsBroadcastReceiver()

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
