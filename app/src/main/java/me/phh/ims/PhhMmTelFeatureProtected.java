
package me.phh.ims;

import android.telephony.ims.feature.MmTelFeature;
import android.telephony.ims.feature.ImsFeature;
import android.telephony.ims.feature.CapabilityChangeRequest;
import android.telephony.Rlog;
import android.telephony.ims.stub.ImsRegistrationImplBase;

import java.util.List;

// intermediate class to MmTelFeature to extend
// changeEnabledCapabilities which cannot be done in kotlin
// see https://stackoverflow.com/questions/49284094/inheritance-from-java-class-with-a-public-method-accepting-a-protected-class-in/49287402#49287402
public class PhhMmTelFeatureProtected extends MmTelFeature {
	private final static String TAG = "Phh MmTelFeatureProtected";
	private int slotId;
	private int capabilities;
	public PhhMmTelFeatureProtected(int slotId) {
		this.slotId = slotId;
		// Set what we want to support here.
		// Android will automatically remove capabilities if
		// something is missing, so setting too many should not
		// cause errors
		this.capabilities =
			MmTelCapabilities.CAPABILITY_TYPE_VOICE |
			MmTelCapabilities.CAPABILITY_TYPE_SMS;
	}

	public void changeEnabledCapabilities(CapabilityChangeRequest capabilityChangeRequest,
			ImsFeature.CapabilityCallbackProxy capabilityCallbackProxy) {
		Rlog.d(TAG, slotId + " changeEnabledCapabilities");

		List<CapabilityChangeRequest.CapabilityPair> toEnable =
			capabilityChangeRequest.getCapabilitiesToEnable();
		toEnable.forEach((pair) -> {
			int cap = pair.getCapability();
			Rlog.d(TAG, "Adding " + cap + " to " + pair.getRadioTech());
			if(pair.getRadioTech() == ImsRegistrationImplBase.REGISTRATION_TECH_LTE) {
				this.capabilities |= cap;
			}
		});

		List<CapabilityChangeRequest.CapabilityPair> toDisable =
			capabilityChangeRequest.getCapabilitiesToDisable();
		toDisable.forEach((pair) -> {
			int cap = pair.getCapability();
			Rlog.d(TAG, "Removing " + cap + " to " + pair.getRadioTech());
			if(pair.getRadioTech() == ImsRegistrationImplBase.REGISTRATION_TECH_LTE) {
				this.capabilities &= ~cap;
			}
		});
		Rlog.d(TAG, "Final capabilities: " + this.capabilities);

		MmTelFeature.MmTelCapabilities capabilities = new MmTelFeature.MmTelCapabilities();
		capabilities.addCapabilities(this.capabilities);
		notifyCapabilitiesStatusChanged(capabilities);
	}
}
