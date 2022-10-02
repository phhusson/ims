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
    override fun onReceive(ctxt: Context, intent: Intent) {
        Rlog.d("PHH", "PhhImsBroadcastReceiver onReceive")
    }
}

class PhhImsService : ImsService() {
    override fun createMmTelFeature(slotId: Int): MmTelFeature {
        Rlog.d("PHH", "ImsService createMmTelFeature")
        return PhhMmTelFeature /*.getInstance*/(slotId)
    }
    override fun createRcsFeature(slotId: Int): RcsFeature? {
        Rlog.d("PHH", "ImsService createRcsFeature")
        return null
    }

    val config = PhhImsConfig()

    override fun getConfig(slotId: Int): ImsConfigImplBase {
        Rlog.d("PHH", "ImsService getConfig")
        return config
    }

    val receiver: PhhImsBroadcastReceiver = PhhImsBroadcastReceiver()

    class LocalBinder : Binder() {
        fun getService(): PhhImsService {
            Rlog.d("PHH", "ImsService LocalBinder getService")
            return PhhImsService()
        }
    }

    // XXX cache one per slot id
    val imsRegistration = ImsRegistrationImplBase()
    override fun getRegistration(slotId: Int): ImsRegistrationImplBase {
        Rlog.d("PHH", "ImsService getRegistration $slotId")
        return imsRegistration
    }

    override fun onCreate() {
        Rlog.d("PHH", "ImsService onCreate")
    }

    override fun onDestroy() {
        Rlog.d("PHH", "ImsService onDestroy")
        instance = null
    }

    override fun readyForFeatureCreation() {
        Rlog.d("PHH", "ImsService readyForFeatureCreation")
        if (instance != null && instance !== this) {
            throw RuntimeException()
        }
        instance = this
    }

    companion object {
        var instance: PhhImsService? = null
        // const val tag = "PhhImsService"
    }
}
