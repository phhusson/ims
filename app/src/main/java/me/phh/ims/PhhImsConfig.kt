package me.phh.ims

import android.os.PersistableBundle
import android.telephony.Rlog
import android.telephony.ims.RcsClientConfiguration
import android.telephony.ims.stub.ImsConfigImplBase

class PhhImsConfig() : ImsConfigImplBase() {
    val intMap = HashMap<Int, Int>()
    val strMap = HashMap<Int, String>()

    override fun setConfig(item: Int, value: Int): /*SetConfigResult*/ Int {
        Rlog.d("PHH", "PhhImsConfig setConfig $item $value")
        intMap.put(item, value)
        return ImsConfigImplBase.CONFIG_RESULT_SUCCESS
    }
    override fun setConfig(item: Int, value: String): /*SetConfigResult*/ Int {
        Rlog.d("PHH", "PhhImsConfig setConfig $item $value")
        strMap.put(item, value)
        return ImsConfigImplBase.CONFIG_RESULT_SUCCESS
    }
    override fun getConfigInt(item: Int): Int {
        Rlog.d("PHH", "PhhImsConfig getConfigInt $item")
        return intMap.get(item) ?: ImsConfigImplBase.CONFIG_RESULT_UNKNOWN
    }
    override fun getConfigString(item: Int): String? {
        Rlog.d("PHH", "PhhImsConfig getConfigString $item")
        return strMap.get(item)
    }
    override fun updateImsCarrierConfigs(bundle: PersistableBundle) {
        Rlog.d("PHH", "PhhImsConfig updateImsCarrierConfigs")
    }
    override fun setRcsClientConfiguration(rcc: RcsClientConfiguration) {
        Rlog.d("PHH", "PhhImsConfig setRcsClientConfiguration")
    }
    override fun triggerAutoConfiguration() {
        Rlog.d("PHH", "PhhImsConfig triggerAutoConfiguration")
    }
}
