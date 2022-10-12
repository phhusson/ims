package me.phh.ims

import android.os.Message
import android.telephony.Rlog
import android.telephony.ims.ImsCallProfile
import android.telephony.ims.feature.CapabilityChangeRequest
import android.telephony.ims.feature.ImsFeature
import android.telephony.ims.feature.MmTelFeature
import android.telephony.ims.stub.ImsCallSessionImplBase
import android.telephony.ims.stub.ImsMultiEndpointImplBase
import android.telephony.ims.stub.ImsRegistrationImplBase.REGISTRATION_TECH_LTE
import android.telephony.ims.stub.ImsSmsImplBase
import android.telephony.ims.stub.ImsUtImplBase
import me.phh.sip.SipHandler

// frameworks/base/telephony/java/android/telephony/ims/feature/MmTelFeature.java
class PhhMmTelFeature(val slotId: Int) : PhhKludgeMmTelFeature(slotId) {
    val imsSms = PhhImsSms(slotId)
    lateinit var sipHandler: SipHandler

    override fun createCallProfile(callSessionType: Int, callType: Int): ImsCallProfile {
        Rlog.d("PHH", "MmTelFeature $slotId createCallProfile $callSessionType $callType")
        // check why not called
        // figure out RilHolder.INSTANCE.getRadios(mSlotId).setImsCfg ? Probably only required
        // if we leave ims to the radio...
        return ImsCallProfile(callSessionType, callType)
    }
    override fun createCallSession(profile: ImsCallProfile): ImsCallSessionImplBase {
        Rlog.d("PHH", "MmTelFeature $slotId createCallSession")
        return ImsCallSessionImplBase()
    }

    fun getInstance(slotId: Int): PhhMmTelFeature {
        Rlog.d("PHH", "MmTelFeature $slotId getInstance")
        return PhhMmTelFeature(slotId)
    }

    /*override*/ fun changeEnabledCapabilities(
        request: CapabilityChangeRequest,
        c: ImsFeature /*.CapabilityCallbackProxy*/
    ) {
        // argument c is protected in ImsFeature, but we extend MmTelFeature which
        // extends ImsFeature so it should be accessible. Retry when building inline
        // with android? for now just roll with it...
        // This function won't be called but a proper stub is implemented in
        // PhhKludgeMmTelFeature
        Rlog.d("PHH", "MmTelFeature $slotId changeEnabledCapabilities")
    }

    override fun getFeatureState(): Int {
        Rlog.d("PHH", "MmTelFeature $slotId getFeatureState")
        // always ready for now... Also STATE_INITIALIZING, STATE_UNAVAILABLE
        return ImsFeature.STATE_READY
    }

    override fun getMultiEndpoint(): ImsMultiEndpointImplBase {
        Rlog.d("PHH", "MmTelFeature $slotId getMultiEndpoint")
        return ImsMultiEndpointImplBase()
    }

    override fun getSmsImplementation(): ImsSmsImplBase {
        Rlog.d("PHH", "MmTelFeature $slotId getSmsImplementation")
        return imsSms
    }

    override fun getUt(): ImsUtImplBase {
        Rlog.d("PHH", "MmTelFeature $slotId getUt")
        return ImsUtImplBase()
    }

    override fun onFeatureReady() {
        Rlog.d("PHH", "MmTelFeature $slotId onFeatureReady")

        // call onRegistering first then
        // register SIP here and call onRegistered after .. register.
        val imsService = PhhImsService.Companion.instance!!
        sipHandler = SipHandler(imsService)
        sipHandler.imsFailureCallback = { imsService.getRegistration(slotId).onDeregistered(null) }
        sipHandler.imsReadyCallback = {
            imsService.getRegistration(slotId).onRegistered(REGISTRATION_TECH_LTE)
        }
        imsSms.sipHandler = sipHandler
        sipHandler.onSmsReceived = imsSms::onSmsReceived
        imsService.getRegistration(slotId).onRegistering(REGISTRATION_TECH_LTE)
        sipHandler.getVolteNetwork()

        /*
         This works!
        thread {
            Rlog.d("PHH", "waiting before sending sms...")
            Thread.sleep(1000);
            Rlog.d("PHH", "Trying to send sms...")
            // pdu from opt/telephony/tests/telephonytests/src/com/android/internal/telephony/GsmSmsTest.java
            // check if compatible with what we get from SIP messages...
            val pdu = "07914151551512f2040B916105551511f100006060605130308A04D4F29C0E".hexToByteArray()
            // first argument is any unique id we want
            // format is 3gpp or 3gpp2
            mImsSms.onSmsReceived(1234123, "3gpp", pdu);
        }
        */
    }

    override fun onFeatureRemoved() {
        Rlog.d("PHH", "MmTelFeature $slotId onFeatureRemoved")
    }

    // ints are @MmTelCapabilities.MmTelCapability and @ImsRegistrationImplBase.ImsRegistrationTech
    override fun queryCapabilityConfiguration(capability: Int, radioTech: Int): Boolean {
        Rlog.d("PHH", "MmTelFeature $slotId queryCapabilityConfiguration $capability $radioTech")
        return capability == MmTelFeature.MmTelCapabilities.CAPABILITY_TYPE_SMS
    }

    override fun setUiTtyMode(mode: Int, onCompleteMessage: Message?) {
        Rlog.d("PHH", "MmTelFeature $slotId setUiTtyMode $onCompleteMessage")
    }

    fun shouldProcessCall(numbers: String): Int {
        // can be used to route outgoing calls without MMS if desired, option?
        // In that case return PORCESS_CALL_CSFB
        Rlog.d("PHH", "MmTelFeature $slotId shouldProcessCall $numbers")
        return 0 /* PROCESS_CALL_IMS */
    }
}
