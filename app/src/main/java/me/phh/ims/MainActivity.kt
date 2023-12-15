//SPDX-License-Identifier: GPL-2.0
package me.phh.ims

import android.annotation.SuppressLint
import android.content.Context
import android.net.*
import android.net.eap.EapSessionConfig
import android.net.ipsec.ike.*
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.system.OsConstants.AF_INET
import android.system.OsConstants.AF_INET6
import android.telephony.Rlog
import android.telephony.SmsMessage
import android.telephony.TelephonyManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.*
import me.phh.sip.*

class MainActivity : AppCompatActivity() {
    var ref: IkeSession? = null
    // var na: NetworkAgent? = null

    fun connectIke(ctxt: Context) {
        val ipsecManager = ctxt.getSystemService(IpSecManager::class.java)
        val nm = ctxt.getSystemService(ConnectivityManager::class.java)

        val tm = ctxt.getSystemService(TelephonyManager::class.java)
        var network: Network? = null

        nm.registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(n: Network) {
                    Rlog.d("PHH", "Got network available $n")
                    network = n
                }
            }
        )

        val mcc = tm.simOperator.substring(0 until 3)
        var mnc = tm.simOperator.substring(3)
        if (mnc.length == 2) mnc = "0$mnc"
        val imsi = tm.subscriberId

        Rlog.d("PHH", "Got mcc $mcc mnc $mnc imsi $imsi")

        val ikeParamsBuilder = IkeSessionParams.Builder()
        // paramsBuilder.setDscp(26)
        ikeParamsBuilder.setServerHostname("epdg.epc.mnc$mnc.mcc$mcc.pub.3gppnetwork.org")
        ikeParamsBuilder.setLocalIdentification(
            IkeRfc822AddrIdentification("0$imsi@nai.epc.mnc$mnc.mcc$mcc.pub.3gppnetwork.org")
        )
        ikeParamsBuilder.setRemoteIdentification(IkeFqdnIdentification("ims"))
        ikeParamsBuilder.setAuthEap(
            null,
            EapSessionConfig.Builder()
                .setEapAkaConfig(1, TelephonyManager.APPTYPE_USIM)
                .setEapIdentity("0$imsi@nai.epc.mnc$mnc.mcc$mcc.pub.3gppnetwork.org".toByteArray())
                .build()
        )
        // This SA proposal works on Bouygues telecom 208 20
        ikeParamsBuilder.addIkeSaProposal(
            IkeSaProposal.Builder()
                .addDhGroup(SaProposal.DH_GROUP_2048_BIT_MODP)
                .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, 256)
                .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128)
                .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_256)
                .build()
        )
        // This SA proposal works on Free Mobile 208 15
        ikeParamsBuilder.addIkeSaProposal(
            IkeSaProposal.Builder()
                .addDhGroup(SaProposal.DH_GROUP_1024_BIT_MODP)
                .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, 128)
                .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1)
                .build()
        )
        // paramsBuilder.setNetwork()
        ikeParamsBuilder.addIkeOption(IkeSessionParams.IKE_OPTION_ACCEPT_ANY_REMOTE_ID)
        // ikeParamsBuilder.addIkeOption(IkeSessionParams.IKE_OPTION_MOBIKE)
        // set lifetime
        // set retransmission
        // set dpd delay

        // Optional in Iwlan, but why would we want any other auth that EAP?!?
        ikeParamsBuilder.addIkeOption(IkeSessionParams.IKE_OPTION_EAP_ONLY_AUTH)
        ikeParamsBuilder.javaClass
            .getMethod("addPcscfServerRequest", Int::class.java)
            .invoke(ikeParamsBuilder, AF_INET)
        ikeParamsBuilder.javaClass
            .getMethod("addPcscfServerRequest", Int::class.java)
            .invoke(ikeParamsBuilder, AF_INET6)
        // Add Ike 3GPP extensions?
        // Set NATT keepalive?
        val childParamsBuilder = TunnelModeChildSessionParams.Builder()
        // This child SA proposal works on Bouygues telecom 208 20
        /*childParamsBuilder.addChildSaProposal(
            ChildSaProposal.Builder()
                .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, 256)
                .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128)
                .build()
        )*/
        // This child SA proposal works on Free Mobile 208 15
        childParamsBuilder.addChildSaProposal(
            ChildSaProposal.Builder()
                .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, 128)
                .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
                .build()
        )
        // set child lifetime
        // set handover infos (original ipv4/ipv6)
        childParamsBuilder.addInternalAddressRequest(AF_INET)
        childParamsBuilder.addInternalAddressRequest(AF_INET6)
        childParamsBuilder.addInternalDnsServerRequest(AF_INET)
        childParamsBuilder.addInternalDnsServerRequest(AF_INET6)
        // set traffic selector?

        var ipsecTunnel: Object? = null
        ipsecManager.javaClass.getMethod(
            "createIpSecTunnelInterface",
            InetAddress::class.java,
            InetAddress::class.java,
            Network::class.java
        )

        val handlerThread = HandlerThread("PHH IMS").also { it.start() }
        val handler = Handler(handlerThread.looper)
        var pcscf: InetAddress? = null
        var sessionConfiguration: IkeSessionConfiguration? = null
        var childConfiguration: ChildSessionConfiguration? = null
        ref =
            IkeSession(
                ctxt,
                ikeParamsBuilder.build(),
                childParamsBuilder.build(),
                { p0 ->
                    handler.post(
                        object : Runnable {
                            override fun run() {
                                try {
                                    p0.run()
                                } catch (t: Throwable) {
                                    Rlog.d("PHH", "Executor failed with", t)
                                }
                            }
                        }
                    )
                },
                object : IkeSessionCallback {
                    override fun onOpened(p0: IkeSessionConfiguration) {
                        Rlog.d(
                            "PHH",
                            "IKE session opened ${p0.ikeSessionConnectionInfo.localAddress} ${p0.ikeSessionConnectionInfo.remoteAddress}"
                        )
                        Rlog.d("PHH", "Bound network is ${nm.boundNetworkForProcess}")
                        ipsecTunnel =
                            ipsecManager.javaClass
                                .getMethod(
                                    "createIpSecTunnelInterface",
                                    InetAddress::class.java,
                                    InetAddress::class.java,
                                    Network::class.java
                                )
                                .invoke(
                                    ipsecManager,
                                    p0.ikeSessionConnectionInfo.localAddress,
                                    p0.ikeSessionConnectionInfo.remoteAddress,
                                    network
                                ) as Object

                        val _pcscf =
                            p0.javaClass.getMethod("getPcscfServers").invoke(p0)
                                as List<InetAddress>
                        Rlog.d("PHH", "IKE session pcscf ${_pcscf.toList()}")
                        pcscf = _pcscf[0]
                        sessionConfiguration = p0
                    }

                    override fun onClosed() {
                        Rlog.d("PHH", "IKE session closed")
                    }
                },
                object : ChildSessionCallback {
                    override fun onOpened(p0: ChildSessionConfiguration) {
                        val internalAddress =
                            p0.javaClass.getMethod("getInternalAddresses").invoke(p0)
                                as List<LinkAddress>
                        Rlog.d("PHH", "IKE child session opened $p0 ${internalAddress.toList()}")
                        for (addr in internalAddress) {
                            Class.forName("android.net.IpSecManager\$IpSecTunnelInterface")
                                .getMethod("addAddress", InetAddress::class.java, Int::class.java)
                                .invoke(ipsecTunnel, addr.address, addr.prefixLength)
                        }
                        childConfiguration = p0

                        Rlog.d(
                            "PHH",
                            "VoWifi tunnel ready at interface ${ipsecTunnel!!.javaClass.getMethod("getInterfaceName")}"
                        )

                        /*
                        Following code manages to create a Network from Android PoV, though it requires access to private APIs (or rather SystemApi)

                        val capabilitiesBuilder =
                            Class.forName("android.net.NetworkCapabilities\$Builder")
                                .getConstructor().newInstance()
                        capabilitiesBuilder.javaClass.getMethod("addTransportType", Int::class.java)
                            .invoke(capabilitiesBuilder, NetworkCapabilities.TRANSPORT_WIFI)
                        capabilitiesBuilder.javaClass.getMethod("addCapability", Int::class.java)
                            .invoke(capabilitiesBuilder, NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        capabilitiesBuilder.javaClass.getMethod("addCapability", Int::class.java)
                            .invoke(
                                capabilitiesBuilder,
                                NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING
                            )
                        capabilitiesBuilder.javaClass.getMethod("addCapability", Int::class.java)
                            .invoke(
                                capabilitiesBuilder,
                                NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED
                            )
                        capabilitiesBuilder.javaClass.getMethod("addCapability", Int::class.java)
                            .invoke(capabilitiesBuilder, NetworkCapabilities.NET_CAPABILITY_XCAP)

                        val capabilities = capabilitiesBuilder.javaClass.getMethod("build")
                            .invoke(capabilitiesBuilder) as NetworkCapabilities
                        val lp = LinkProperties()
                        lp.interfaceName = ipsecTunnel!!.javaClass.getMethod("getInterfaceName")
                            .invoke(ipsecTunnel) as String
                        lp.javaClass.getMethod("setLinkAddresses", Collection::class.java)
                            .invoke(lp, internalAddress)
                        val ipv6DefaultPrefix =
                            IpPrefix::class.java.getConstructor(
                                InetAddress::class.java,
                                Int::class.java
                            )
                                .newInstance(Inet6Address.getByName("::"), 0)
                        val route =
                            RouteInfo::class.java.getConstructor(
                                IpPrefix::class.java,
                                InetAddress::class.java,
                                String::class.java,
                                Int::class.java
                            )
                                .newInstance(
                                    ipv6DefaultPrefix,
                                    InetAddress.getByName("::"),
                                    lp.interfaceName,
                                    1
                                )
                        lp.addRoute(route)
                        lp.javaClass.getMethod("addPcscfServer", InetAddress::class.java)
                            .invoke(lp, pcscf)

                        val configBuilder = Class.forName("android.net.NetworkAgentConfig\$Builder")
                            .getConstructor().newInstance()
                        configBuilder.javaClass.getMethod("setLegacyTypeName", String::class.java)
                            .invoke(configBuilder, "USB")
                        configBuilder.javaClass.getMethod(
                            "setNat64DetectionEnabled",
                            Boolean::class.java
                        ).invoke(configBuilder, false)
                        configBuilder.javaClass.getMethod(
                            "setProvisioningNotificationEnabled",
                            Boolean::class.java
                        ).invoke(configBuilder, false)
                        val config = configBuilder.javaClass.getMethod("build")
                            .invoke(configBuilder)


                        val networkProvider = Class.forName("android.net.NetworkProvider").getConstructor(Context::class.java, Looper::class.java, String::class.java).newInstance(ctxt, handlerThread.looper, "PHH-IMS")

                        na = object : NetworkAgent(
                            ctxt,
                            handlerThread.looper,
                            "PHH-IMS",
                            capabilities,
                            lp,
                            10,
                            config,
                            networkProvider
                        ) {
                        }

                        na!!.register()
                        na!!.markConnected()*/
                    }

                    override fun onClosed() {
                        Rlog.d("PHH", "IKE child session closed")
                    }

                    override fun onIpSecTransformCreated(p0: IpSecTransform, p1: Int) {
                        Rlog.d("PHH", "IPSec session created $p0 $p1")

                        ipsecManager.javaClass
                            .getMethod(
                                "applyTunnelModeTransform",
                                Class.forName("android.net.IpSecManager\$IpSecTunnelInterface"),
                                Int::class.java,
                                IpSecTransform::class.java
                            )
                            .invoke(ipsecManager, ipsecTunnel, p1, p0)
                    }

                    override fun onIpSecTransformDeleted(p0: IpSecTransform, p1: Int) {
                        Rlog.d("PHH", "IPSec session deleted $p0 $p1")
                    }
                }
            )
    }

    fun updateStatus(str: String) {
        Rlog.d("PHH", str)
        runOnUiThread {
            val status = findViewById<TextView>(R.id.status)
            status.text = str + "\n" + status.text
        }
    }
    /*
        if (false) {
            val targetPhoneNumber = "XXXXXXX"

            val smsManager =
                getSystemService(SmsManager::class.java).createForSubscriptionId(subId)
            val smscStr = smsManager.smscAddress
            val smscMatchRegex = Regex("([0-9]+)")
            val smsc = smscMatchRegex.find(smscStr!!)!!.groupValues[1]

            val sms = encodeSms(smsc, targetPhoneNumber, "not hello")
            val msg4 =
                """
            MESSAGE sip:+$smsc@$realm SIP/2.0
            Via: SIP/2.0/TCP [$myAddr2]:${socketInIpsec.localPort};branch=$branch;rport
            From: <sip:$mySip>;tag=$tag
            Max-Forwards: 70
            Expires: 600000
            To: <sip:+$smsc@$realm>
            Content-Type: application/vnd.3gpp.sms
            Call-ID: $callId
            CSeq: 4 MESSAGE
            User-Agent: Xiaomi__Android_12_MIUI220208
            Security-Verify: $securityServer
            P-Preferred-Identity: <sip:$mySip>
            Route: $route
            Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
            P-Asserted-Identity: <sip:$mySip>
            Content-Length: ${sms!!.size}
            """.trimIndent()

            updateStatus("Sending SMS")
    */
    fun encodeSms(scAddress: String, destinationAddress: String, message: String): ByteArray? {
        val t = SmsMessage.getSubmitPdu(scAddress, destinationAddress, message, false)
        val pdu = t.encodedMessage
        val headerSize = 3
        val scSize = t.encodedScAddress?.size ?: 0
        val v = ByteArray(pdu.size + headerSize + scSize + 1)
        v[0] = 0
        v[1] = 0x22 // What is that?!? RP Message Reference
        v[2] = 0
        if (t.encodedScAddress != null) System.arraycopy(t.encodedScAddress, 0, v, 3, scSize)
        v[3 + scSize] = pdu.size.toByte()
        System.arraycopy(pdu, 0, v, 3 + scSize + 1, pdu.size)
        return v
    }

    fun parseSms(msg: ByteArray) {
        var currentMsg = msg.toList()
        val msgType = msg[0]
        if (msgType != 1.toByte()) return
        val msgRef = msg[1]
        currentMsg = currentMsg.drop(2)
        val originatorScLength = currentMsg[0].toInt() // Network to MS
        currentMsg = currentMsg.drop(1)

        val originatorSc = currentMsg.take(originatorScLength).toByteArray()
        currentMsg = currentMsg.drop(originatorScLength)

        val destinationLength = currentMsg[0].toInt()
        currentMsg = currentMsg.drop(1)

        val destination = currentMsg.take(destinationLength).toByteArray()
        currentMsg = currentMsg.drop(destinationLength)
        val pduSize = currentMsg[0]
        currentMsg = currentMsg.drop(1)

        // Prepend fake 0 for 0 scAddress ?!?
        val msg = SmsMessage.createFromPdu((listOf(0.toByte()) + currentMsg).toByteArray())
        Rlog.d(
            "PHH",
            "Received SMS from ${msg.originatingAddress} also ${msg.displayOriginatingAddress} val ${msg.messageBody}"
        )
        updateStatus("Received SMS from ${msg.displayOriginatingAddress} val ${msg.messageBody}")
    }

    @SuppressLint("MissingPermission")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        /*thread {
            connectIke(this)
        }*/
    }
}
