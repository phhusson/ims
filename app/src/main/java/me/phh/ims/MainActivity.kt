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
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.FileDescriptor
import java.net.*
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    // in Key: Value extract value
    val extractValueRegex = Regex("^[^:]*: *(.*)")
    fun extractValue(line: String): String? {
        val v = extractValueRegex.find(line) ?: return null
        return v.groupValues[1]
    }

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

    @SuppressLint("HardwareIds", "MissingPermission")
    fun launchIms(network: Network) {
        updateStatus("Got IMS network. Launching SIP")

        val ipsecManager = getSystemService(IpSecManager::class.java)
        val nm = getSystemService(ConnectivityManager::class.java)
        val tm = getSystemService(TelephonyManager::class.java)
        val sm = getSystemService(SubscriptionManager::class.java)
        val subscriptions = sm.activeSubscriptionInfoList
        val activeSubscription = subscriptions[0]
        val subId = activeSubscription.subscriptionId
        val imei = tm.getDeviceId(activeSubscription.simSlotIndex)
        val sipInstance =
            "<urn:gsma:imei:" + imei.substring(0, 8) + "-" + imei.substring(8, 14) + "-0>"

        val mcc = tm.simOperator.substring(0 until 3)
        val mnc = tm.simOperator.substring(3).let { if (it.length == 2) "0$it" else it }
        val imsi = tm.subscriberId

        Thread.sleep(3000)
        Rlog.d("PHH", "XCAP+WIFI transport available ${network}")
        val (myAddr, pcscfAddr) =
            {
                val lp = nm.getLinkProperties(network)
                val caps = nm.getNetworkCapabilities(network)
                Rlog.d("PHH", " caps = $caps, lp = $lp")
                val pcscfs =
                    lp!!.javaClass.getMethod("getPcscfServers").invoke(lp) as List<InetAddress>
                lp.linkAddresses[0].address to pcscfs[0]
            }()
        val myAddrString = myAddr.hostAddress
        val realm = "ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
        val user = "$imsi@ims.mnc$mnc.mcc$mcc.3gppnetwork.org"

        Rlog.d("PHH", "My addr $myAddrString")
        try {
            updateStatus("Connecting to SIP")

            val socketFactory = network.socketFactory
            val socket = socketFactory.createSocket(pcscfAddr, 5060)

            updateStatus("Registering 1")

            Rlog.d("PHH", "Socket opened!")
            val myAddr2 = socket.localAddress.hostAddress

            val socketInIpsec = socketFactory.createSocket()
            socketInIpsec.bind(InetSocketAddress(socket.localAddress, 0))
            val serverSocket = ServerSocket()
            val serverSocketFd =
                serverSocket.javaClass.getMethod("getFileDescriptor\$").invoke(serverSocket)
                    as FileDescriptor
            serverSocket.bind(InetSocketAddress(socket.localAddress, socketInIpsec.localPort + 1))
            network.bindSocket(serverSocketFd)

            val writer = socket.getOutputStream()
            val reader = socket.getInputStream().sipReader()
            val localPort = socketInIpsec.localPort

            val mySPI1 = ipsecManager.allocateSecurityParameterIndex(myAddr)
            val mySPI2 = ipsecManager.allocateSecurityParameterIndex(myAddr, mySPI1.spi + 1)

            fun secClient(ealg: String, alg: String) =
                "ipsec-3gpp;prot=esp;mod=trans;spi-c=${mySPI1.spi};spi-s=${mySPI2.spi};port-c=${localPort};port-s=${serverSocket.localPort};ealg=${ealg};alg=${alg}"
            val secClientLine =
                "Security-Client: ${secClient("null", "hmac-sha-1-96")}, ${secClient("aes-cbc", "hmac-sha-1-96")}"
            val msg =
                SipRequest(
                    SipMethod.REGISTER,
                    "sip:$realm",
                    """
                        Via: SIP/2.0/TCP [$myAddr2]:${socket.localPort};rport
                        From: <sip:$user>
                        To: <sip:$user>
                        Expires: 600000
                        Contact: <sip:$imsi@[$myAddr2]:${socket.localPort};transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio

                        Supported: path, gruu, sec-agree
                        Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                        Authorization: Digest username="$user",realm="$realm",nonce="",uri="sip:$realm",response="",algorithm=AKAv1-MD5
                        Require: sec-agree
                        Proxy-Require: sec-agree
                        $secClientLine
                    """.toSipHeadersMap()
                )
            Rlog.d("PHH", "Sending $msg")

            writer.write(msg.toByteArray())

            val reply = reader.parseMessage()!!
            Rlog.d("PHH", "received: $reply")
            // XXX keep open for TCP keepalive
            socket.close()
            Rlog.d("PHH", "Socket closed!")

            updateStatus("Register 1 answered with ${reply.firstLine}")
            // assert SipResponse && code 401?

            val (wwwAuthenticateType, wwwAuthenticateParams) =
                reply.headers["www-authenticate"]!![0].getAuthValues()
            require(wwwAuthenticateType == "Digest")
            val nonceB64 = wwwAuthenticateParams["nonce"]!!

            updateStatus("Requesting AKA challenge")
            val akaResult = sipAkaChallenge(tm, nonceB64)

            val securityServer = reply.headers["security-server"]!!
            val (securityServerType, securityServerParams) =
                reply.headers["security-server"]!!
                    .map { it.getParams() }
                    .sortedByDescending { it.component2()["q"]?.toFloat() ?: 0.toFloat() }[0]
            require(securityServerType == "ipsec-3gpp")

            val portS = securityServerParams["port-s"]!!.toInt()
            // spi string is 32 bit unsigned, but ipsecManager wants an int...
            val spiS = securityServerParams["spi-s"]!!.toUInt().toInt()
            val serverSPI = ipsecManager.allocateSecurityParameterIndex(pcscfAddr, spiS)

            val portC = securityServerParams["port-c"]!!.toInt()
            val spiC = securityServerParams["spi-c"]!!.toUInt().toInt()
            val serverSPIC = ipsecManager.allocateSecurityParameterIndex(pcscfAddr, spiC)

            // pad key to 160 bits (original ik size 128 + 32 bits)
            val hmac_key = akaResult.ik + ByteArray(4)

            val outgoingTransform =
                IpSecTransform.Builder(this)
                    .setAuthentication(IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, hmac_key, 96))
                    .also {
                        if (securityServerParams["ealg"] == "aes-cbc") {
                            it.setEncryption(
                                IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck)
                            )
                        }
                    }
                    .buildTransportModeTransform(myAddr, serverSPI)

            val ingoingTransform =
                IpSecTransform.Builder(this)
                    .setAuthentication(IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, hmac_key, 96))
                    .also {
                        if (securityServerParams["ealg"] == "aes-cbc") {
                            it.setEncryption(
                                IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck)
                            )
                        }
                    }
                    .buildTransportModeTransform(pcscfAddr, mySPI1)

            ipsecManager.applyTransportModeTransform(
                socketInIpsec,
                IpSecManager.DIRECTION_IN,
                ingoingTransform
            )
            ipsecManager.applyTransportModeTransform(
                socketInIpsec,
                IpSecManager.DIRECTION_OUT,
                outgoingTransform
            )

            // IPSec for server
            if (true) {
                val outgoingTransformC =
                    IpSecTransform.Builder(this)
                        .setAuthentication(
                            IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, hmac_key, 96)
                        )
                        .also {
                            if (securityServerParams["ealg"] == "aes-cbc") {
                                it.setEncryption(
                                    IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck)
                                )
                            }
                        }
                        .buildTransportModeTransform(myAddr, serverSPIC)

                val ingoingTransformC =
                    IpSecTransform.Builder(this)
                        .setAuthentication(
                            IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, hmac_key, 96)
                        )
                        .also {
                            if (securityServerParams["ealg"] == "aes-cbc") {
                                it.setEncryption(
                                    IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck)
                                )
                            }
                        }
                        .buildTransportModeTransform(pcscfAddr, mySPI2)

                ipsecManager.applyTransportModeTransform(
                    serverSocketFd,
                    IpSecManager.DIRECTION_IN,
                    ingoingTransformC
                )
                ipsecManager.applyTransportModeTransform(
                    serverSocketFd,
                    IpSecManager.DIRECTION_OUT,
                    outgoingTransformC
                )
                thread {
                    while (true) {
                        val client = serverSocket.accept()
                        thread {
                            Rlog.d("PHH", "Got new client!")
                            val clientReader = client.getInputStream().sipReader()
                            val clientWriter = client.getOutputStream()
                            while (true) {
                                val msg = clientReader.parseMessage()!!
                                Rlog.d("PHH", "Client sent $msg")
                                updateStatus("Unsolicited ${msg.firstLine}")

                                if (msg !is SipRequest) {
                                    // ignore Responses or invalid messages except for logs
                                    Rlog.d(
                                        "PHH",
                                        "Not responding to ${msg.javaClass.kotlin.qualifiedName}"
                                    )
                                    continue
                                }

                                if (msg.method == SipMethod.MESSAGE) {
                                    try {
                                        parseSms(msg.body)
                                    } catch (t: Throwable) {
                                        Rlog.d("PHH", "Failed parsing message", t)
                                    }
                                }

                                val reply =
                                    SipResponse(
                                        statusCode = 200,
                                        statusString = "OK",
                                        headersParam =
                                            msg.headers.filter { (k, _) ->
                                                k in listOf("cseq", "via", "from", "to", "call-id")
                                            }
                                    )
                                Rlog.d("PHH", "Replying back with $reply")
                                clientWriter.write(reply.toByteArray())

                                // also send MESSAGE back for protocol ack,
                                // need to check where to send on tcp
                            }
                        }
                    }
                }
            }

            updateStatus("Connecting to IPsec socket")
            Rlog.d("PHH", "Connecting to IPSec socket")
            socketInIpsec.connect(InetSocketAddress(pcscfAddr, portS))
            updateStatus("Connected to IPsec socket")
            Rlog.d("PHH", "Succeeded!")

            val ipsecWriter = socketInIpsec.getOutputStream()
            val ipsecReader = socketInIpsec.getInputStream().sipReader()

            val akaDigest =
                AkaDigest(
                    user = user,
                    realm = realm,
                    uri = "sip:$realm",
                    nonceB64 = nonceB64,
                    opaque = wwwAuthenticateParams["opaque"],
                    akaResult = akaResult,
                )

            // Contact +sip.instance="<urn:gsma:imei:86687905-321566-0>";
            val branch = msg.headers["via"]!![0].getParams().component2()["branch"]!!
            val msg2 =
                SipRequest(
                    SipMethod.REGISTER,
                    "sip:$realm",
                    msg.headers +
                        ("security-verify" to securityServer) +
                        // via/contact only IP changes: somehow make it variable?
                        // for further register refreshes, auth and cseq only should be incremented
                        """
                            Via: SIP/2.0/TCP [$myAddr2]:${socketInIpsec.localPort};branch=$branch;rport
                            Contact: <sip:$imsi@[$myAddr2]:${socketInIpsec.localPort};transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio
                            Authorization: $akaDigest
                            CSeq: 2 REGISTER
                        """.toSipHeadersMap()
                )

            updateStatus("Sending register 2")
            Rlog.d("PHH", "Sending $msg2")
            ipsecWriter.write(msg2.toByteArray())

            val reply2 = ipsecReader.parseMessage()!!
            Rlog.d("PHH", "Received $reply2")
            // require reply 200 ?
            val associatedUri =
                reply2.headers["p-associated-uri"]!!.map {
                    it.trimStart('<').trimEnd('>').split(':')
                }
            val myPhoneNumber = associatedUri.first { it[0] == "tel" }[1]
            val mySip = associatedUri.first { it[0] == "sip" }[1]
            val route =
                (reply2.headers.getOrDefault("service-route", emptyList()) +
                        reply2.headers.getOrDefault("path", emptyList()))
                    .toSet() // set to remove duplicates
                    .joinToString(", ")
            updateStatus("Received register 2 answer ${reply2.firstLine}, phone $myPhoneNumber")

            Rlog.d("PHH", "Got my sip = $mySip, my number = $myPhoneNumber")

            val msg3 =
                SipRequest(
                    SipMethod.SUBSCRIBE,
                    "sip:$mySip",
                    """
                        Via: SIP/2.0/TCP [$myAddr2]:${socketInIpsec.localPort};branch=z9hG4bK_test1234;rport
                        P-Preferred-Identity: <sip:$mySip>
                        From: <sip:$mySip>
                        To: <sip:$mySip>
                        Event: reg
                        Expires: 600000
                        Route: $route
                        Contact: <sip:$myPhoneNumber@[$myAddr2]:${socketInIpsec.localPort};transport=tcp>;expires=600000;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio
                        Supported: sec-agree
                        Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                        Require: sec-agree
                        Proxy-Require: sec-agree
                    """.toSipHeadersMap() +
                        ("security-verify" to securityServer)
                )

            Rlog.d("PHH", "Sending $msg3")

            updateStatus("Subscribing...")
            ipsecWriter.write(msg3.toByteArray())

            val reply3 = ipsecReader.parseMessage()!!
            Rlog.d("PHH", "IPSEC Received < $reply3")

            updateStatus("Subscribe returned ${reply3.firstLine}}")
            // TODO check reply 200?
            Rlog.d("PHH", "End of susbcribe answer")

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
                Rlog.d("PHH", "Sending $msg4")

                ipsecWriter.write(msg4.replace("\n", "\r\n").toByteArray())
                ipsecWriter.write("\r\n".toByteArray())
                ipsecWriter.write("\r\n".toByteArray())
                ipsecWriter.write(sms)

                lines.clear()
                for (line in ipsecReader.lines()) {
                    lines.add(line.trim())
                    Rlog.d("PHH", "IPSEC Received < $line")
                    if (line.trim() == "") break
                }
                updateStatus("SMS returned ${lines[0]}")
                Rlog.d("PHH", "End of send SMS return")
            }
            */

            while (true) {
                val msg5 = ipsecReader.parseMessage()
                if (msg5 == null) break
                Rlog.d("PHH", "IPSEC Received < $msg5")
            }

            Rlog.d("PHH", "End of socket")

            socketInIpsec.close()
        } catch (e: Throwable) {
            Rlog.d("PHH", "Connecting SIP socket", e)
        }
    }

    @SuppressLint("HardwareIds", "MissingPermission")
    fun launchVolteNetwork() {
        val nm = getSystemService(ConnectivityManager::class.java)
        val tm = getSystemService(TelephonyManager::class.java)
        updateStatus("Requesting IMS network.")

        val sm = getSystemService(SubscriptionManager::class.java)
        val subscriptions = sm.activeSubscriptionInfoList
        val activeSubscription = subscriptions[0]
        val subId = activeSubscription.subscriptionId
        val imei = tm.getDeviceId(activeSubscription.simSlotIndex)

        nm.registerNetworkCallback(
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .setNetworkSpecifier(subId.toString())
                .addCapability(NetworkCapabilities.NET_CAPABILITY_IMS)
                // .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                // .addCapability(NetworkCapabilities.NET_CAPABILITY_XCAP)
                .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    updateStatus("Got IMS network.")
                    launchIms(network)
                }
            }
        )
        Thread.sleep(120 * 1000L)
    }

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

        // thread { launchVolteNetwork() }
    }
}
