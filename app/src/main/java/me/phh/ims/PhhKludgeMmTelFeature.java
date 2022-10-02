
package me.phh.ims;

import android.telephony.ims.feature.MmTelFeature;
import android.telephony.ims.feature.ImsFeature;
import android.telephony.ims.feature.CapabilityChangeRequest;

import android.util.Log;
import java.util.List;

public class PhhKludgeMmTelFeature extends MmTelFeature {
	private int slotId;
	private int capabilities;
	public PhhKludgeMmTelFeature(int slotId) {
		this.slotId = slotId;
		this.capabilities = 8;
	}

	public void changeEnabledCapabilities(CapabilityChangeRequest capabilityChangeRequest, ImsFeature.CapabilityCallbackProxy capabilityCallbackProxy) {
		Log.d("PHH", "PhhKludgeMmTelFeature " + slotId + " changeEnabledCapabilities");

		List<CapabilityChangeRequest.CapabilityPair> toEnable =
			capabilityChangeRequest.getCapabilitiesToEnable();
		toEnable.forEach((pair) -> {
			int cap = pair.getCapability();
			Log.d("PHH", "Adding " + cap);
			this.capabilities |= cap;
		});
		List<CapabilityChangeRequest.CapabilityPair> toDisable =
			capabilityChangeRequest.getCapabilitiesToDisable();
		toDisable.forEach((pair) -> {
			int cap = pair.getCapability();
			Log.d("PHH", "Removing " + cap);
			this.capabilities &= ~cap;
		});
		Log.d("PHH", "Final capabilities: " + this.capabilities);

		MmTelFeature.MmTelCapabilities capabilities = new MmTelFeature.MmTelCapabilities();
		capabilities.addCapabilities(this.capabilities);
		notifyCapabilitiesStatusChanged(capabilities);
	}
}
