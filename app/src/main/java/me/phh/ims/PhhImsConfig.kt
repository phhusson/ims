//SPDX-License-Identifier: GPL-2.0
package me.phh.ims

import android.os.PersistableBundle
import android.telephony.Rlog
import android.telephony.ims.RcsClientConfiguration
import android.telephony.ims.stub.ImsConfigImplBase

class PhhImsConfig() : ImsConfigImplBase() {
    companion object {
        private const val TAG = "PHH ImsConfig"
    }

    val intMap = HashMap<Int, Int>()
    val strMap = HashMap<Int, String>()

    override @SetConfigResult fun setConfig(item: Int, value: Int): Int {
        Rlog.d(TAG, "setConfig $item $value")
        intMap.put(item, value)
        return ImsConfigImplBase.CONFIG_RESULT_SUCCESS
    }
    override @SetConfigResult fun setConfig(item: Int, value: String): Int {
        Rlog.d(TAG, "setConfig $item $value")
        strMap.put(item, value)
        return ImsConfigImplBase.CONFIG_RESULT_SUCCESS
    }
    override fun getConfigInt(item: Int): Int {
        Rlog.d(TAG, "getConfigInt $item")
        return intMap.get(item) ?: ImsConfigImplBase.CONFIG_RESULT_UNKNOWN
    }
    override fun getConfigString(item: Int): String? {
        Rlog.d(TAG, "getConfigString $item")
        return strMap.get(item)
    }
    override fun updateImsCarrierConfigs(bundle: PersistableBundle) {
        Rlog.d(TAG, "updateImsCarrierConfigs")
    }
    override fun setRcsClientConfiguration(rcc: RcsClientConfiguration) {
        Rlog.d(TAG, "setRcsClientConfiguration")
    }
    override fun triggerAutoConfiguration() {
        Rlog.d(TAG, "triggerAutoConfiguration")
    }
}
