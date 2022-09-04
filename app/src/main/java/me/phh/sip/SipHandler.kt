package me.phh.sip

import android.content.Context
import android.net.ConnectivityManager
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.telephony.Rlog
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import java.io.OutputStream
import java.net.InetAddress
import kotlin.concurrent.thread

class SipHandler(val ctxt: Context) {
    val subscriptionManager: SubscriptionManager
    val telephonyManager: TelephonyManager
    val connectivityManager: ConnectivityManager
    val ipSecManager: IpSecManager
    init {
        subscriptionManager = ctxt.getSystemService(SubscriptionManager::class.java)
        telephonyManager = ctxt.getSystemService(TelephonyManager::class.java)
        connectivityManager = ctxt.getSystemService(ConnectivityManager::class.java)
        ipSecManager = ctxt.getSystemService(IpSecManager::class.java)
    }

    val activeSubscription = subscriptionManager.activeSubscriptionInfoList[0]
    val imei = telephonyManager.getDeviceId(activeSubscription.simSlotIndex)
    val subId = activeSubscription.subscriptionId
    val mcc = telephonyManager.simOperator.substring(0 until 3)
    var mnc = telephonyManager.simOperator.substring(3).let { if (it.length == 2) "0$it" else it }
    val imsi = telephonyManager.subscriberId

    val realm = "ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
    val user = "$imsi@$realm"
    var akaDigest =
        """Digest username="$user",realm="$realm",nonce="",uri="sip:$realm",response="",algorithm=AKAv1-MD5"""

    var registerCounter = 1
    var registerHeaders =
        """
        From: <sip:$user>
        To: <sip:$user>
        Call-ID: ${randomBytes(12).toHex()}
    """.toSipHeadersMap()
    var commonHeaders = "".toSipHeadersMap()

    // too many lateinit, bad separation?
    lateinit var localAddr: InetAddress
    lateinit var pcscfAddr: InetAddress

    lateinit var clientSpiC: IpSecManager.SecurityParameterIndex
    lateinit var clientSpiS: IpSecManager.SecurityParameterIndex

    lateinit var network: Network

    lateinit var plainSocket: SipConnectionTcp
    lateinit var socket: SipConnectionTcp
    lateinit var serverSocket: SipConnectionTcpServer

    fun parseMessage(reader: SipReader, writer: OutputStream): Boolean {
        val msg = reader.parseMessage()
        Rlog.d("PHH", "Received message $msg")
        if (msg is SipResponse) {
            return handleResponse(msg, writer)
        }
        if (msg !is SipRequest) {
            // invalid message,stop tryng
            Rlog.d("PHH", "Got invalid message, closing socket!")
            return false
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
        writer.write(reply.toByteArray())

        return true
    }

    fun handleResponse(response: SipResponse, writer: OutputStream): Boolean {
        // response must keep branch (via), tag (from->to), cseq and call-id
        // ideally have a locked place where we store call ids we want to reply to,
        // but for now just hardcode based on cseq patterns...
        when (response.headers["cseq"]!![0].split(" ")[1]) {
            "REGISTER" -> {
                // once we get there all register must be successful
                // on failure just abort thread, ims will restart
                require(response.statusCode == 200)

                val route =
                    (response.headers.getOrDefault("service-route", emptyList()) +
                            response.headers.getOrDefault("path", emptyList()))
                        .toSet() // remove duplicates
                        .toList()

                val associatedUri =
                    response.headers["p-associated-uri"]!!.map {
                        it.trimStart('<').trimEnd('>').split(':')
                    }
                val mySip = associatedUri.first { it[0] == "sip" }[1]
                commonHeaders +=
                    mapOf(
                        "route" to route,
                        "from" to listOf("<sip:$mySip>"),
                        "to" to listOf("<sip:$mySip>"),
                    )

                subscribe(writer, "sip:$mySip")
            }
            "SUBSCRIBE" -> {
                // require(response.statusCode == 200)
                // XXX signal error to mmtelfeature for backed off retry
            }
        }

        return true
    }

    fun connect() {
        Rlog.d("PHH", "SipHandler connect")
        val lp = connectivityManager.getLinkProperties(network)
        val pcscfs = lp!!.javaClass.getMethod("getPcscfServers").invoke(lp) as List<InetAddress>
        val pcscf = pcscfs[0]

        localAddr = lp.linkAddresses[0].address
        pcscfAddr = pcscf

        clientSpiC = ipSecManager.allocateSecurityParameterIndex(localAddr)
        clientSpiS = ipSecManager.allocateSecurityParameterIndex(localAddr, clientSpiC.spi + 1)

        plainSocket = SipConnectionTcp(network, pcscfAddr)
        plainSocket.connect(5060)
        socket = SipConnectionTcp(network, pcscfAddr, plainSocket.localAddr)
        serverSocket =
            SipConnectionTcpServer(network, pcscfAddr, plainSocket.localAddr, socket.localPort + 1)

        updateCommonHeaders(plainSocket)
        register(plainSocket.writer)
        val plainRegReply = plainSocket.reader.parseMessage()
        Rlog.d("PHH", "Received $plainRegReply")
        plainSocket.close()
        if (plainRegReply !is SipResponse || plainRegReply.statusCode != 401) {
            Rlog.w("PHH", "Didn't get expected response from initial register, aborting")
            // XXX signal failure to MmTelFeature for controlled retry
            return
        }

        val (wwwAuthenticateType, wwwAuthenticateParams) =
            plainRegReply.headers["www-authenticate"]!![0].getAuthValues()
        require(wwwAuthenticateType == "Digest")
        val nonceB64 = wwwAuthenticateParams["nonce"]!!

        Rlog.d("PHH", "Requesting AKA challenge")
        val akaResult = sipAkaChallenge(telephonyManager, nonceB64)
        akaDigest =
            SipAkaDigest(
                    user = user,
                    realm = realm,
                    uri = "sip:$realm",
                    nonceB64 = nonceB64,
                    opaque = wwwAuthenticateParams["opaque"],
                    akaResult = akaResult
                )
                .toString()
        val securityServer = plainRegReply.headers["security-server"]!!
        commonHeaders += ("security-verify" to securityServer)
        registerHeaders += ("security-verify" to securityServer)
        val (securityServerType, securityServerParams) =
            securityServer
                .map { it.getParams() }
                .sortedByDescending { it.component2()["q"]?.toFloat() ?: 0.toFloat() }[0]
        require(securityServerType == "ipsec-3gpp")

        val portS = securityServerParams["port-s"]!!.toInt()
        // spi string is 32 bit unsigned, but ipSecManager wants an int...
        val spiS = securityServerParams["spi-s"]!!.toUInt().toInt()
        val serverSpiS = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiS)

        // val portC = securityServerParams["port-c"]!!.toInt()
        val spiC = securityServerParams["spi-c"]!!.toUInt().toInt()
        val serverSpiC = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiC)

        val ealg = securityServerParams["ealg"]
        // SHA1-96 mac key must be 160 bits, pad ik
        val hmac_key = akaResult.ik + ByteArray(4)
        val ipSecBuilder =
            IpSecTransform.Builder(ctxt)
                .setAuthentication(IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, hmac_key, 96))
                .also {
                    if (ealg == "aes-cbc") {
                        it.setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck))
                    }
                }

        socket.enableIpsec(ipSecBuilder, ipSecManager, clientSpiC, serverSpiS)
        serverSocket.enableIpsec(ipSecBuilder, ipSecManager, clientSpiS, serverSpiC)
        socket.connect(portS)
        updateCommonHeaders(socket)
        register(socket.writer)
        val regReply = socket.reader.parseMessage()!!
        Rlog.d("PHH", "Received $regReply")

        if (regReply !is SipResponse || regReply.statusCode != 200) {
            Rlog.w("PHH", "Could not connect, aborting SIP")
            // XXX signal failure to MmTelFeature? just throwing an exception
            // would restart the whole IMS stack, but we don't really want to
            // do that without some throttling as trying to register in a tight
            // loop could get us banned
            return
        }
        handleResponse(regReply, socket.writer)

        // we registered! Kick in thread to register every 3000s
        thread {
            while (true) {
                Thread.sleep(3_000_000)
                register(socket.writer)
                // don't try to read reply, main thread will
            }
        }

        // two ways we'll get incoming messages:
        // - reply to normal socket (just read forever)
        // - connection to server socket
        // start both in threads as we're only called here from network
        // callback from which it's better to return
        thread {
            while (parseMessage(socket.reader, socket.writer)) {}
            socket.close()
        }
        thread {
            while (true) {
                val client = serverSocket.serverSocket.accept()
                // there can only be a single client at a time because
                // both source and destination ports are fixed
                val reader = client.getInputStream().sipReader()
                val writer = client.getOutputStream()
                while (parseMessage(reader, writer)) {}
                client.close()
            }
        }
    }

    fun getVolteNetwork() {
        // TODO add something similar for VoWifi ipsec tunnel?
        Rlog.d("PHH", "Requesting IMS network")
        connectivityManager.registerNetworkCallback(
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .setNetworkSpecifier(subId.toString())
                .addCapability(NetworkCapabilities.NET_CAPABILITY_IMS)
                .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(_network: Network) {
                    Rlog.d("PHH", "Got IMS network.")
                    network = _network
                    connect()
                }
            }
        )
    }

    fun updateCommonHeaders(socket: SipConnectionTcp) {
        val local = "[${socket.localAddr.hostAddress}]:${socket.localPort}"
        val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
        val newHeaders =
            """
                 Via: SIP/2.0/TCP $local;rport
                 Contact: <sip:$imsi@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio
                 """.toSipHeadersMap()
        registerHeaders += newHeaders
        commonHeaders += newHeaders
    }

    fun register(writer: OutputStream) {
        // XXX samsung rom apparently regenerates local SPIC/SPIS every register,
        // this doesn't affect current connections but possibly affects new incoming
        // connections ? Just keep it constant for now
        // XXX samsung doesn't increment cnonce but it would be better to avoid replays?
        // well that'd only matter if the server refused replays, so keep as is.
        // XXX timeout/retry? notification on fail? receive on thread?
        fun secClient(ealg: String, alg: String) =
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=${clientSpiC.spi};spi-s=${clientSpiS.spi};port-c=${socket.localPort};port-s=${serverSocket.localPort};ealg=${ealg};alg=${alg}"
        val secClientLine =
            "Security-Client: ${secClient("null", "hmac-sha-1-96")}, ${secClient("aes-cbc", "hmac-sha-1-96")}"

        val msg =
            SipRequest(
                SipMethod.REGISTER,
                "sip:$realm",
                registerHeaders +
                    """
                 Expires: 600000
                 Cseq: $registerCounter REGISTER
                 Supported: path, gruu, sec-agree
                 Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                 Authorization: $akaDigest
                 Require: sec-agree
                 Proxy-Require: sec-agree
                 $secClientLine
            """.toSipHeadersMap()
            ) // route present on all calls except this
        Rlog.d("PHH", "Sending $msg")
        writer.write(msg.toByteArray())
        registerCounter += 1
    }

    fun subscribe(writer: OutputStream, mySip: String) {
        val msg =
            SipRequest(
                SipMethod.SUBSCRIBE,
                "$mySip",
                commonHeaders +
                    """
            P-Preferred-Identity: <$mySip>
            Event: reg
            Expires: 600000
            Supported: sec-agree
            Require: sec-agree
            Proxy-Require: sec-agree
            Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
            """.toSipHeadersMap()
            )
        Rlog.d("PHH", "Sending $msg")
        writer.write(msg.toByteArray())
    }
}
