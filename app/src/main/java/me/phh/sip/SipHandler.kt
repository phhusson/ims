//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.annotation.SuppressLint
import android.content.Context
import android.media.*
import android.net.*
import android.os.Handler
import android.os.HandlerThread
import android.telephony.PhoneNumberUtils
import android.telephony.Rlog
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.telephony.imsmedia.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import me.phh.ims.Rnnoise
import java.io.*
import java.net.*
import java.util.*
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

private data class smsHeaders(
    val dest: String,
    val callId: String,
    val cseq: String,
)

class SipHandler(val ctxt: Context) {
    companion object {
        private const val TAG = "PHH SipHandler"
    }

    val myHandler = Handler(HandlerThread("PhhMmTelFeature").apply { start() }.looper)
    val myExecutor = Executor { p0 -> myHandler.post(p0) }
    val imsMediaManager = ImsMediaManager(ctxt, myExecutor, object:
        ImsMediaManager.OnConnectedCallback {
        override fun onConnected() {
            Rlog.d(TAG, "ImsMediaManager connected")
        }

        override fun onDisconnected() {
            Rlog.d(TAG, "ImsMediaManager disconnected")
        }
    })

    private val subscriptionManager: SubscriptionManager
    private val telephonyManager: TelephonyManager
    private val connectivityManager: ConnectivityManager
    private val ipSecManager: IpSecManager
    init {
        subscriptionManager = ctxt.getSystemService(SubscriptionManager::class.java)
        telephonyManager = ctxt.getSystemService(TelephonyManager::class.java)
        connectivityManager = ctxt.getSystemService(ConnectivityManager::class.java)
        ipSecManager = ctxt.getSystemService(IpSecManager::class.java)
    }

    @SuppressLint("MissingPermission")
    private val activeSubscription = subscriptionManager.activeSubscriptionInfoList[0]
    private val imei = telephonyManager.getDeviceId(activeSubscription.simSlotIndex)
    private val subId = activeSubscription.subscriptionId
    private val mcc = telephonyManager.simOperator.substring(0 until 3)
    private var mnc =
        telephonyManager.simOperator.substring(3).let { if (it.length == 2) "0$it" else it }
    private val imsi = telephonyManager.subscriberId

    private val realm = "ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
    private val user = "$imsi@$realm"
    private var akaDigest =
        """Digest username="$user",realm="$realm",nonce="",uri="sip:$realm",response="",algorithm=AKAv1-MD5"""

    fun generateCallId(): SipHeadersMap {
        val callId = randomBytes(12).toHex()
        return mapOf("call-id" to listOf(callId))
    }
    private var registerCounter = 1
    private var registerHeaders =
        """
        From: <sip:$user>
        To: <sip:$user>
        """.toSipHeadersMap() + generateCallId()
    private var commonHeaders = "".toSipHeadersMap()
    private var contact = ""
    private var mySip = ""
    private var myTel = ""

    // too many lateinit, bad separation?
    lateinit private var localAddr: InetAddress
    lateinit private var pcscfAddr: InetAddress

    data class SipIpsecSettings(
        val clientSpiC: IpSecManager.SecurityParameterIndex,
        val clientSpiS: IpSecManager.SecurityParameterIndex,
        val serverSpiC: IpSecManager.SecurityParameterIndex? = null,
        val serverSpiS: IpSecManager.SecurityParameterIndex? = null,
    )
    lateinit var ipsecSettings: SipIpsecSettings

    lateinit private var network: Network

    lateinit private var plainSocket: SipConnectionTcp
    lateinit private var socket: SipConnectionTcp
    lateinit private var serverSocket: SipConnectionTcpServer
    lateinit private var serverSocketUdp: SipConnectionUdp
    private var reliableSequenceCounter = 67

    private val cbLock = ReentrantLock()
    private var requestCallbacks: Map<SipMethod, ((SipRequest) -> Int)> = mapOf()
    private var responseCallbacks: Map<String, ((SipResponse) -> Boolean)> = mapOf()
    private var imsReady = false
    var imsReadyCallback: (() -> Unit)? = null
    var imsFailureCallback: (() -> Unit)? = null
    var onSmsReceived: ((Int, String, ByteArray) -> Unit)? = null
    var onSmsStatusReportReceived: ((Int, String, ByteArray) -> Unit)? = null
    var onIncomingCall: ((handle: Object, from: String, extras: Map<String, String>) -> Unit)? =
        null
    var onCancelledCall: ((handle: Object, from: String, extras: Map<String, String>) -> Unit)? =
        null
    private val smsLock = ReentrantLock()
    private var smsToken = 0
    private val smsHeadersMap = mutableMapOf<Int, smsHeaders>()

    fun setRequestCallback(method: SipMethod, cb: (SipRequest) -> Int) {
        cbLock.withLock { requestCallbacks += (method to cb) }
    }
    fun setResponseCallback(callId: String, cb: (SipResponse) -> Boolean) {
        cbLock.withLock { responseCallbacks += (callId to cb) }
    }

    fun parseMessage(reader: SipReader, writer: OutputStream): Boolean {
        val msg =
            try {
                reader.parseMessage()
            } catch (e: SocketException) {
                Rlog.d(TAG, "Got exception $e")
                if ("$e" == "java.net.SocketException: Try again") {
                    // we sometimes seem to get EAGAIN
                    return true
                }
                throw e
            }
        Rlog.d(TAG, "RObject() message $msg")
        if (msg is SipResponse) {
            return handleResponse(msg)
        }
        if (msg !is SipRequest) {
            // invalid message, stop trying
            Rlog.d(TAG, "Got invalid message, closing socket!")
            return false
        }

        val requestCb = cbLock.withLock { requestCallbacks[msg.method] }
        var status = 200
        // XXX default requestCb = notification?
        if (requestCb != null) {
            status = requestCb(msg)
        }
        if(status == 0) return true
        val reply =
            SipResponse(
                statusCode = status,
                statusString = if (status == 200) "OK" else if (status == 100) "Trying" else "ERROR",
                headersParam =
                    msg.headers.filter { (k, _) ->
                        k in listOf("cseq", "via", "from", "to", "call-id")
                    }
            )
        Rlog.d(TAG, "Replying back with $reply")
        synchronized(writer) { writer.write(reply.toByteArray()) }

        return true
    }

    fun handleResponse(response: SipResponse): Boolean {
        val callId = response.headers["call-id"]?.get(0)
        if (callId == null) {
            // message without call-id should never happen, close connection
            return false
        }
        val responseCb = cbLock.withLock { responseCallbacks[callId] }
        if (responseCb == null) {
            // nothing to do
            return true
        }

        if (responseCb(response)) {
            // remove callback if done
            cbLock.withLock { responseCallbacks -= callId }
        }
        return true
    }

    var abandonnedBecauseOfNoPcscf = false
    fun connect() {
        abandonnedBecauseOfNoPcscf = false
        Rlog.d(TAG, "Trying to connect to SIP server")
        val lp = connectivityManager.getLinkProperties(network)
        Rlog.d(TAG, "Got link properties $lp")
        val pcscfs = (lp!!.javaClass.getMethod("getPcscfServers").invoke(lp) as List<*>).sortedBy { if(it is Inet6Address) 0 else 1 }
        val pcscf = if (pcscfs.isNotEmpty()) {
            pcscfs[0] as InetAddress
        } else {
            Rlog.w(TAG, "Had no Pcscf Sever defined, aborting")
            val t = try { InetAddress.getByName("ims.mnc${mnc}.mcc${mcc}.pub.3gppnetwork.org") } catch(t: Throwable) { null }
            val t2 = try { InetAddress.getByName("ims.mnc${mnc}.mcc${mcc}.3gppnetwork.org") } catch(t: Throwable) { null }
            Rlog.d(TAG, "Resolved $t and $t2")
            //imsFailureCallback?.invoke()
            abandonnedBecauseOfNoPcscf = true
            return
        }

        localAddr = lp.linkAddresses.map { it.address }.sortedBy { if(it is Inet6Address) 0 else 1 }.first()
        pcscfAddr = pcscf

        Rlog.w(TAG, "Connecting with address $localAddr to $pcscfAddr")

        val clientSpiC = ipSecManager.allocateSecurityParameterIndex(localAddr)
        val clientSpiS = ipSecManager.allocateSecurityParameterIndex(localAddr, clientSpiC.spi + 1)
        ipsecSettings = SipIpsecSettings(
            clientSpiS = clientSpiS,
            clientSpiC = clientSpiC)

        plainSocket = SipConnectionTcp(network, pcscfAddr, localAddr)
        plainSocket.connect(5060)
        socket = SipConnectionTcp(network, pcscfAddr, plainSocket.localAddr)
        serverSocket =
            SipConnectionTcpServer(network, pcscfAddr, plainSocket.localAddr, socket.localPort + 1)
        serverSocketUdp =
            SipConnectionUdp(network, pcscfAddr, plainSocket.localAddr, socket.localPort + 1)

        updateCommonHeaders(plainSocket)
        register(plainSocket.writer)
        val plainRegReply = plainSocket.reader.parseMessage()
        Rlog.d(TAG, "Received $plainRegReply")
        plainSocket.close()
        if (plainRegReply !is SipResponse || plainRegReply.statusCode != 401) {
            Rlog.w(TAG, "Didn't get expected response from initial register, aborting")
            imsFailureCallback?.invoke()
            return
        }

        val (wwwAuthenticateType, wwwAuthenticateParams) =
            plainRegReply.headers["www-authenticate"]!![0].getAuthValues()
        require(wwwAuthenticateType == "Digest")
        val nonceB64 = wwwAuthenticateParams["nonce"]!!

        Rlog.d(TAG, "Requesting AKA challenge")
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
        val supported_alg = listOf("hmac-sha-1-96", "hmac-md5-96")
        val supported_ealg = listOf("aes-cbc", "null")
        val (securityServerType, securityServerParams) =
            securityServer
                .map { it.getParams() }
                .filter {
                    val thisEAlg = it.component2()["ealg"] ?: "null"
                    supported_ealg.contains(thisEAlg)
                }
                .filter { supported_alg.contains(it.component2()["alg"]) }
                .sortedByDescending { it.component2()["q"]?.toFloat() ?: 0.toFloat() }[0]
        require(securityServerType == "ipsec-3gpp")

        val portS = securityServerParams["port-s"]!!.toInt()
        // spi string is 32 bit unsigned, but ipSecManager wants an int...
        val spiS = securityServerParams["spi-s"]!!.toUInt().toInt()
        val serverSpiS = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiS)

        val spiC = securityServerParams["spi-c"]!!.toUInt().toInt()
        val serverSpiC = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiC)

        ipsecSettings = SipIpsecSettings(
            clientSpiS = clientSpiS,
            clientSpiC = clientSpiC,
            serverSpiC = serverSpiC,
            serverSpiS = serverSpiS)

        val ealg = securityServerParams["ealg"] ?: "null"
        val (alg, hmac_key) = if (securityServerParams["alg"] == "hmac-sha-1-96") {
            // sha-1-96 mac key must be 160 bits, pad ik
            IpSecAlgorithm.AUTH_HMAC_SHA1 to akaResult.ik + ByteArray(4)
        } else {
            IpSecAlgorithm.AUTH_HMAC_MD5 to akaResult.ik
        }
        val ipSecBuilder =
            IpSecTransform.Builder(ctxt)
                .setAuthentication(IpSecAlgorithm(alg, hmac_key, 96))
                .also {
                    if (ealg == "aes-cbc") {
                        it.setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, akaResult.ck))
                    }
                }

        val serverInTransform = ipSecBuilder.buildTransportModeTransform(pcscfAddr, clientSpiS)
        val serverOutTransform = ipSecBuilder.buildTransportModeTransform(localAddr, serverSpiC)
        socket.enableIpsec(ipSecBuilder, ipSecManager, clientSpiC, serverSpiS)
        serverSocket.enableIpsec(ipSecManager, serverInTransform, serverOutTransform)
        serverSocketUdp.enableIpsec(ipSecManager, serverInTransform, serverOutTransform)
        socket.connect(portS)
        updateCommonHeaders(socket)
        register()
        val regReply = socket.reader.parseMessage()!!
        Rlog.d(TAG, "Received $regReply")

        if (regReply !is SipResponse || regReply.statusCode != 200) {
            Rlog.w(TAG, "Could not connect, aborting SIP")
            imsFailureCallback?.invoke()
            return
        }

        setResponseCallback(registerHeaders["call-id"]!![0], ::registerCallback)
        setRequestCallback(SipMethod.MESSAGE, ::handleSms)
        setRequestCallback(SipMethod.INVITE, ::handleCall)
        setRequestCallback(SipMethod.PRACK, ::handlePrack)
        setRequestCallback(SipMethod.CANCEL, ::handleCancel)
        setRequestCallback(SipMethod.BYE, ::handleCancel)
        setRequestCallback(SipMethod.UPDATE, ::handleUpdate)
        handleResponse(regReply)

        // two ways we'll get incoming messages:
        // - reply to normal socket (just read forever)
        // - connection to server socket
        // start both in threads as we're only called here from network
        // callback from which it's better to return
        CoroutineScope(Dispatchers.IO).launch {
            // XXX catch and reconnect on 'java.net.SocketException: Software caused connection
            // abort' ?
            while (parseMessage(socket.reader, socket.writer)) {}
            socket.close()
        }
        CoroutineScope(Dispatchers.IO).launch {
            while (true) {
                // XXX catch and reconnect on 'java.net.SocketException: Socket closed' ?
                val client = serverSocket.serverSocket.accept()
                // there can only be a single client at a time because
                // both source and destination ports are fixed
                val reader = client.getInputStream().sipReader()
                val writer = client.getOutputStream()
                while (parseMessage(reader, writer)) {}
                client.close()
            }
        }
        CoroutineScope(Dispatchers.IO).launch {
            val bufferIn = ByteArray(128*1024)
            val dgramPacketIn = DatagramPacket(bufferIn, bufferIn.size)
            val writer = ByteArrayOutputStream()
            while (true) {
                serverSocketUdp.socket.receive(dgramPacketIn)
                Rlog.d(TAG, "Received dgram packet")
                val baIs = ByteArrayInputStream(dgramPacketIn.data, dgramPacketIn.offset, dgramPacketIn.length)
                val reader = baIs.sipReader()
                while (parseMessage(reader, writer)) {}
                val writerOut = writer.toByteArray()
                val dgramPacketOut = DatagramPacket(writerOut, writerOut.size, dgramPacketIn.address, dgramPacketIn.port)
                serverSocketUdp.socket.send(dgramPacketOut)
                writer.reset()
            }
        }
    }

    fun getVolteNetwork() {
        // TODO add something similar for VoWifi ipsec tunnel?
        Rlog.d(TAG, "Requesting IMS network")
        connectivityManager.requestNetwork(NetworkRequest.Builder()
            //.addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            //.addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            //.setNetworkSpecifier(subId.toString())
            .addCapability(NetworkCapabilities.NET_CAPABILITY_IMS)
            //.addCapability(NetworkCapabilities.NET_CAPABILITY_MMTEL)
            .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onUnavailable() {
                    Rlog.d(TAG, "IMS network unavailable")
                }

                override fun onLost(network: Network) {
                    Rlog.d(TAG, "IMS network lost")
                }

                override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                    Rlog.d(TAG, "IMS network blocked status changed $blocked")
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities
                ) {
                    Rlog.d(TAG, "IMS network capabilities changed $networkCapabilities")
                }

                override fun onLosing(network: Network, maxMsToLive: Int) {
                    Rlog.d(TAG, "IMS network losing")
                }

                override fun onLinkPropertiesChanged(
                    _network: Network,
                    linkProperties: LinkProperties
                ) {
                    Rlog.d(TAG, "IMS network link properties changed $linkProperties")
                    val pcscfs = linkProperties!!.javaClass.getMethod("getPcscfServers").invoke(linkProperties) as List<*>
                    Rlog.d(TAG, "Got pcscfs $pcscfs")
                    if(pcscfs.isNotEmpty() && abandonnedBecauseOfNoPcscf) {
                        connect()
                    }
                }

                override fun onAvailable(_network: Network) {
                    Rlog.d(TAG, "Got IMS network.")
                    if (!this@SipHandler::network.isInitialized) {
                        network = _network
                        thread {
                            Thread.sleep(4000)
                            connect()
                        }
                    } else {
                        Rlog.d(TAG, "... don't try anything")
                    }
                }
            }
        )
    }

    fun updateCommonHeaders(socket: SipConnectionTcp) {
        val local = "[${socket.localAddr.hostAddress}]:${serverSocket.localPort}"
        val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
        contact =
            """<sip:$imsi@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
        val newHeaders =
            """
            Via: SIP/2.0/TCP $local;rport
            """.toSipHeadersMap()
        registerHeaders += newHeaders
        commonHeaders += newHeaders
    }

    fun register(_writer: OutputStream? = null) {
        // XXX samsung rom apparently regenerates local SPIC/SPIS every register,
        // this doesn't affect current connections but possibly affects new incoming
        // connections ? Just keep it constant for now
        // XXX samsung doesn't increment cnonce but it would be better to avoid replays?
        // well that'd only matter if the server refused replays, so keep as is.
        // XXX timeout/retry? notification on fail? receive on thread?

        val writer = _writer ?: socket.writer

        fun secClient(alg: String, ealg: String) =
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=${ipsecSettings.clientSpiC.spi};spi-s=${ipsecSettings.clientSpiS.spi};port-c=${socket.localPort};port-s=${serverSocket.localPort};ealg=${ealg};alg=${alg}"

        val algs = listOf("hmac-sha-1-96", "hmac-md5-96")
        val ealgs = listOf("null", "aes-cbc")
        val secClients = algs.flatMap { alg -> ealgs.map { ealg -> secClient(alg, ealg) }}
        val secClientLine =
            "Security-Client: ${secClients.joinToString(", ")}"

        val msg =
            SipRequest(
                SipMethod.REGISTER,
                "sip:$realm",
                registerHeaders +
                    """
                    Expires: 600000
                    Cseq: $registerCounter REGISTER
                    Contact: $contact
                    Supported: path, gruu, sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                    Authorization: $akaDigest
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    $secClientLine
                    """.toSipHeadersMap()
            ) // route present on all calls except this
        Rlog.d(TAG, "Sending $msg")
        synchronized(writer) { writer.write(msg.toByteArray()) }
        registerCounter += 1
    }

    fun registerCallback(response: SipResponse): Boolean {
        // once we get there all register must be successful
        // on failure just abort thread, ims will restart
        require(response.statusCode == 200)

        val r =  Regex("lr;[^>]*")
        val route =
            (response.headers.getOrDefault("service-route", emptyList()) +
                    response.headers.getOrDefault("path", emptyList()))
                .toSet() // remove duplicates
                .toList()
                .map {
                    r.replace(it, "lr")
                }

        val associatedUri =
            response.headers["p-associated-uri"]!!.map { it.trimStart('<').trimEnd('>').split(':') }
        mySip = "sip:" + associatedUri.first { it[0] == "sip" }[1]
        myTel = associatedUri.first { it[0] == "tel" }[1]
        commonHeaders +=
            mapOf(
                "route" to route,
                "from" to listOf("<$mySip>"),
                "to" to listOf("<$mySip>"),
            )

        subscribe()
        // always keep callback
        return false
    }

    fun subscribe() {
        val local = "[${socket.localAddr.hostAddress}]:${serverSocket.localPort}"
        val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
        val contactTel =
            """<sip:$myTel@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
        val msg =
            SipRequest(
                SipMethod.SUBSCRIBE,
                "$mySip",
                commonHeaders +
                    """
                    Contact: $contactTel
                    P-Preferred-Identity: <$mySip>
                    Event: reg
                    Expires: 600000
                    Supported: sec-agree
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, INFO, MESSAGE, PRACK, OPTIONS
                    Accept: application/reginfo+xml
                    P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=20810b8c49752501
                    """.toSipHeadersMap()
            )
        if (!imsReady) {
            setResponseCallback(msg.headers["call-id"]!![0], ::subscribeCallback)
        }
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }
    }

    fun subscribeCallback(response: SipResponse): Boolean {
        if (response.statusCode != 200) {
            imsFailureCallback?.invoke()
            return true
        }
        imsReadyCallback?.invoke()
        imsReady = true
        return true
    }

    fun waitPrack(v: Int) {
        synchronized(prAckWaitLock) {
            while (prAckWait.contains(v)) {
                prAckWaitLock.wait(1000)
            }
        }
    }

    fun handlePrack(request: SipRequest): Int {
        Rlog.d(TAG, "Received PRACK for ${request.headers["rack"]!![0]}")
        synchronized(prAckWaitLock) {
            val id = request.headers["rack"]!![0].split(" ")[0].toInt()
            prAckWait -= id
            prAckWaitLock.notifyAll()
        }
        return 200
    }

    fun handleUpdate(request: SipRequest): Int {
        val call = currentCall!!
        val ipType = if(call.rtpRemoteAddr is Inet6Address) "IP6" else "IP4"
        val allTracks = listOf(call.amrTrack, call.dtmfTrack).sorted()
        val mySdp = """
v=0
o=- 1 2 IN $ipType ${socket.localAddr.hostAddress}
s=phh voice call
c=IN $ipType ${socket.localAddr.hostAddress}
b=AS:38
b=RS:0
b=RR:0
t=0 0
m=audio ${call.rtpSocket.localPort} RTP/AVP ${allTracks.joinToString(" ")}
b=AS:38
b=RS:0
b=RR:0
a=rtpmap:${call.amrTrack} AMR/8000/1
a=rtpmap:${call.dtmfTrack} telephone-event/8000
a=${call.amrTrackDesc}
a=ptime:20
a=maxptime:240
a=${call.dtmfTrackDesc}
a=curr:qos local sendrecv
a=curr:qos remote sendrecv
a=des:qos mandatory local sendrecv
a=des:qos mandatory remote sendrecv
a=sendrecv
                       """.trim().toByteArray()

        currentCall = Call(
            outgoing =  call.outgoing,
            amrTrack = call.amrTrack,
            amrTrackDesc = call.amrTrackDesc,
            dtmfTrack = call.dtmfTrack,
            dtmfTrackDesc = call.dtmfTrackDesc,
            callHeaders = call.callHeaders,
            rtpRemoteAddr = call.rtpRemoteAddr,
            rtpRemotePort = call.rtpRemotePort,
            rtpSocket = call.rtpSocket,
            sdp = request.body)

        val reply =
            SipResponse(
                statusCode = 200,
                statusString = "OK",
                headersParam =
                request.headers.filter { (k, _) ->
                    k in listOf("cseq", "via", "from", "to", "call-id")
                } + """
                    Content-Type: application/sdp
                    Supported: 100rel, replaces, timer
                    Require: precondition
                    Call-ID: ${currentCall!!.callHeaders["call-id"]!![0]}
                """.toSipHeadersMap(),
                body = mySdp
            )
        Rlog.d(TAG, "Replying back with $reply")
        synchronized(socket.writer) { socket.writer.write(reply.toByteArray()) }

        if(call?.outgoing == false) {
            val myHeaders2 = call.callHeaders - "rseq" - "content-type" - "require"
            val msg2 =
                SipResponse(
                    statusCode = 180,
                    statusString = "Ringing",
                    headersParam = myHeaders2
                )
            Rlog.d(TAG, "Sending $msg2")
            synchronized(socket.writer) { socket.writer.write(msg2.toByteArray()) }
        }

        return 0
    }

    fun handleCancel(request: SipRequest): Int {
        callStopped.set(true)
        Rlog.d(TAG, "Cancelled call ${request.headers["call-id"]!![0]}")

        currentCall?.imsMediaSession?.let { imsMediaManager.closeSession(it) }

        // We're supposed to add an additional answer SIP/2.0 487 Request Terminated
        onCancelledCall?.invoke(Object(), "", emptyMap())
        return 200
    }

    data class Call(
        val outgoing: Boolean,
        val callHeaders: SipHeadersMap,
        val sdp: ByteArray,
        val amrTrack: Int,
        val amrTrackDesc: String,
        val dtmfTrack: Int,
        val dtmfTrackDesc: String,
        val rtpRemoteAddr: InetAddress,
        val rtpRemotePort: Int,
        val rtpSocket: DatagramSocket,
        val imsMediaSession: ImsMediaSession? = null
    )


    @SuppressLint("MissingPermission")
    fun callEncodeThread() {
        val call = currentCall!!
        thread {
            var sequenceNumber = 0

            val encoder = MediaCodec.createEncoderByType("audio/3gpp")
            val mediaFormat = MediaFormat.createAudioFormat("audio/3gpp", 8000, 1)
            mediaFormat.setInteger(MediaFormat.KEY_BIT_RATE, 12200)
            encoder.configure(mediaFormat, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            encoder.start()

            while(!callStarted.get()) {
                val timestamp = sequenceNumber * 160
                Thread.sleep(20)
                val rtpHeader = listOf(
                    // RTP
                    0x80, //rtp version
                    call.amrTrack, //payload type
                    (sequenceNumber shr 8), (sequenceNumber and 0xff),
                    (timestamp shr 24), ((timestamp shr 16) and 0xff), ((timestamp shr 8) and 0xff), (timestamp and 0xff),
                    0x03, 0x00, 0xd2, 0x00, //SSRC
                )
                val amrNothing = listOf(0x77, 0xc0) // CMR = 12.2kbps, F=0, FT=15=No TX/No RX, Q=1

                val buf = (rtpHeader + amrNothing).map { it.toUByte() }.toUByteArray().toByteArray()

                val dgramPacket =
                    DatagramPacket(buf, buf.size, call.rtpRemoteAddr, call.rtpRemotePort)
                call.rtpSocket.send(dgramPacket)
                sequenceNumber++
            }

            val rnnNoise = Rnnoise()

            // DANGER: Don't open the mic before the user acknowledged opening the call!

            val minBufferSize = AudioRecord.getMinBufferSize(8000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
            val audioRecord = AudioRecord(MediaRecorder.AudioSource.VOICE_COMMUNICATION, 8000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, minBufferSize)

            audioRecord.startRecording()

            var firstPacket = true

            val bufferSize = ((minBufferSize + (rnnNoise.getFrameSize() - 1 )) / rnnNoise.getFrameSize()).toInt() * rnnNoise.getFrameSize()
            Rlog.e(TAG, "Chosing buffersize $bufferSize")
            val buffer = ByteArray(bufferSize)
            val bufferPostRnnoise = ByteArray(bufferSize)
            while (true) {
                if (callStopped.get()) break
                val nRead = audioRecord.read(buffer,0, buffer.size)
                // Convert buffer from ByteArray to ShortArray
                rnnNoise.processFrame(buffer, bufferPostRnnoise)

                val inBufIdx = encoder.dequeueInputBuffer(-1)
                val inBuf = encoder.getInputBuffer(inBufIdx)!!
                inBuf.clear()
                inBuf.put(bufferPostRnnoise, 0, nRead)

                // Fake timestamp but it is not appearing in the output stream anyway
                encoder.queueInputBuffer(inBufIdx, 0, nRead, System.nanoTime() / 1000, 0)

                val outBufInfo = MediaCodec.BufferInfo()
                val outBufIdx = encoder.dequeueOutputBuffer(outBufInfo, 0)
                if (outBufIdx >= 0) {
                    val outBuf = encoder.getOutputBuffer(outBufIdx)!!

                    val encoderData = ByteArray(outBufInfo.size)
                    outBuf.get(encoderData)
                    encoder.releaseOutputBuffer(outBufIdx, false)

                    var bufPos = 0
                    while(bufPos < outBufInfo.size) {
                        val frameSize = 32 // Read from encoderData[0]

                        // Every 20ms, at 8kHz, we have 160 samples
                        val timestamp = sequenceNumber * 160
                        val rtpHeader = listOf(
                            // RTP
                            0x80, //rtp version
                            ( if(firstPacket) 0x80 else 0 ) or call.amrTrack, //payload type
                            (sequenceNumber shr 8), (sequenceNumber and 0xff),
                            (timestamp shr 24), ((timestamp shr 16) and 0xff), ((timestamp shr 8) and 0xff), (timestamp and 0xff),
                            0x03, 0x00, 0xd2, 0x00, //SSRC
                        )
                        firstPacket = false

                        val ft = (encoderData[bufPos + 0].toUInt().toInt() shr 3) and 0xf
                        val cmr = 7 // we want to announce we want the 12.2kbps profile
                        val f = 0
                        val q = 1
                        val firstByte = (cmr shl 4) or (f shl 3) or (ft shr 1)
                        val secondByte = ( (ft and 1) shl 7) or (q shl 6) or (encoderData[bufPos + 1].toUInt().toInt() shr 2)

                        val nextBytes = (1 until (frameSize - 1)).map { i ->
                            // Take 2 bits left, 6 bits right
                            val left = (encoderData[bufPos + i].toUByte().toUInt().toInt() and 0x3) shl 6
                            val right = (encoderData[bufPos + i + 1].toUByte().toUInt().toInt() shr 2) and 0x3f
                            left or right
                        }
                        // Need to know the size in **bits** to know whether we include the lastByte or not
                        // Anyway in mode = 7 = 12.2KHz, we don't.
                        //val lastByte = (encoderData[bufPos + frameSize - 1].toUByte().toUInt().toInt() and 0x3) shl 6

                        val buf = (rtpHeader + firstByte + secondByte + nextBytes /*+ lastByte*/).map { it.toUByte() }.toUByteArray().toByteArray()

                        val dgramPacket =
                            DatagramPacket(buf, buf.size, call.rtpRemoteAddr, call.rtpRemotePort)
                        call.rtpSocket.send(dgramPacket)

                        sequenceNumber++
                        bufPos += frameSize
                    }
                }
            }
            audioRecord.stop()
            audioRecord.release()
            encoder.stop()
            encoder.release()
        }
    }

    var currentCall: Call? = null
    fun acceptCall() {
        thread {

            val local = "[${socket.localAddr.hostAddress}]:${serverSocket.localPort}"
            val sipInstance = "<urn:gsma:imei:${imei.substring(0, 8)}-${imei.substring(8, 14)}-0>"
            val evolvedContact =
                """<sip:$imsi@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio;+g.3gpp.mid-call;+g.3gpp.srvcc-alerting;+g.3gpp.ps2cs-srvcc-orig-pre-alerting"""

            Rlog.d(TAG, "Accepting call")
            val call = currentCall!!
            val myHeaders = call.callHeaders
            val myHeaders3 = myHeaders - "rseq" - "security-verify" + """
                Session-Expires: 900;refresher=uas
                P-Preferred-Identity: <$mySip>
                Contact: $evolvedContact
                Content-Type: application/sdp
                """.toSipHeadersMap()

            // Normally we shouldn't send again the SDP. With "precondition" feature flag, the SDP in 183 Session Progress (then updated in UPDATE) should be used instead
            // But for some yet unknown reason, I need to do it (even though it contradicts my pcaps)
            val msg3 =
                SipResponse(
                    statusCode = 200,
                    statusString = "OK",
                    headersParam = myHeaders3,
                    body = call.sdp
                )
            Rlog.d(TAG, "Sending $msg3")
            synchronized(socket.writer) { socket.writer.write(msg3.toByteArray()) }

            callStarted.set(true)
        }
    }

    fun prack(resp: SipResponse) {
        val who = extractDestinationFromContact(resp.headers["contact"]!![0])
        val callId = resp.headers["call-id"]!![0]
        val rseq = resp.headers["rseq"]!![0]
        val whatToPrack = "$rseq ${resp.headers["cseq"]!![0]}"
        val msg =
            SipRequest(
                SipMethod.PRACK,
                who,
                headersParam = commonHeaders + """
                    RAck: $whatToPrack
                    Require: sec-agree
                    To: ${resp.headers["to"]!![0]}
                    From: ${resp.headers["from"]!![0]}
                    Call-Id: $callId
                    """.toSipHeadersMap()
            )
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }
    }

    fun rejectCall() {
        thread {
            val call = currentCall!!
            val headers = call.callHeaders
            val mySeqCounter = reliableSequenceCounter++
            val myHeaders = headers + "RSeq: $mySeqCounter".toSipHeadersMap()
            val msg =
                SipResponse(
                    statusCode = 486,
                    statusString = "Busy Here",
                    headersParam = myHeaders
                )
            Rlog.d(TAG, "Sending $msg")
            synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }

            callStopped.set(true)
            onCancelledCall?.invoke(Object(), "", emptyMap())
        }
    }

    fun terminateCall() {
        // IDK what packet do we send, but at least we're close rtp
        currentCall?.imsMediaSession?.let { imsMediaManager.closeSession(it) }
        callStopped.set(true)

        onCancelledCall?.invoke(Object(), "", emptyMap())
    }

    /*
    Note: local/remote none/sendrecv are the precondition extension status.
    They basically mean that local/remote are pre-allocating resources before fulfilling the call

    Outgoing call process:
    (Note: If not specified, Requests are local => remote, response are remote => local)
    1. INVITE with SDP containing none current status, and all tracks we can support
    2. (useless) 100 Trying
    3. 183 Session Progress with SDP containing none current status, but selected one track and Rseq
    4. PRACK 183's RSeq and wait for its 200 OK PRACK
    5. UPDATE with SDP containing local sendrecv and remote none (We're starting decoding/encoding, but don't open mic)
    6. 200 OK UPDATE with SDP containing local sendrecv and remote sendrecv (precondition fullfilled)
    7. 183 Session Progress on the INVITE (no SDP, no PRACK)
    8. UPDATE from remote to local with final SDP (precondition infos can be absent)
    9. 200 OK UPDATE from local to remote with our final SDP
    10. 180 Ringing on INVITE (meaning it's actually ringing on the other side)
    11. 200 OK on INVITE (meaning the call is accepted) (opening mic)
    12. ACK (no answer?)

    Call is now running
    During call, remote will regularly send 200 OK on INVITE to keep alive (we have the timer extension enabled)
    We probably need to keep sending UPDATE-s regularly to keep alive
     */

    var respInFlight: SipResponse? = null
    fun call(phoneNumber: String) {
        thread {

            val rtpSocket = DatagramSocket(0, localAddr)
            val fakeRtcpSocket = DatagramSocket(0, localAddr) //useless but annoying ImsMediaManager
            network.bindSocket(rtpSocket)
            //rtpSocket.connect(rtpRemoteAddr, rtpRemotePort.toInt())

            val amrTrack = 97
            val amrTrackDesc = "fmtp:97 mode-change-capability=2;octet-align=0;max-red=0"
            val dtmfTrack = 100
            val dtmfTrackDesc = "fmtp:100 0-15"
            val allTracks = listOf(amrTrack,dtmfTrack).sorted()

            val ipType = if(localAddr is Inet6Address) "IP6" else "IP4"

            val sdp = """
v=0
o=- 1 2 IN $ipType ${socket.localAddr.hostAddress}
s=phh voice call
c=IN $ipType ${socket.localAddr.hostAddress}
b=AS:38
b=RS:0
b=RR:0
t=0 0
m=audio ${rtpSocket.localPort} RTP/AVP ${allTracks.joinToString(" ")}
b=AS:38
b=RS:0
b=RR:0
a=ptime:20
a=maxptime:240
a=rtpmap:$amrTrack AMR/8000/1
a=rtpmap:$dtmfTrack telephone-event/8000
a=fmtp:$amrTrack mode-change-capability=2;octet-align=0;max-red=0
a=fmtp:$dtmfTrack 0-15
a=curr:qos local none
a=curr:qos remote none
a=des:qos optional local sendrecv
a=des:qos optional remote sendrecv
a=sendrecv
                       """.trim().toByteArray()

            val to = "tel:$phoneNumber;phone-context=ims.mnc$mnc.mcc$mcc.3gppnetwork.org"
            val sipInstance = "<urn:gsma:imei:${imei.substring(0, 8)}-${imei.substring(8, 14)}-0>"
            val local = "[${socket.localAddr.hostAddress}]:${serverSocket.localPort}"
            val contactTel =
                """<sip:$myTel@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
            val myHeaders = commonHeaders +
                """
                    From: <$mySip>
                    To: <$to>
                    P-Preferred-Identity: <$mySip>
                    P-Asserted-Identity: <$mySip>
                    Expires: 600000
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
                    P-Early-Media: supported
                    Content-Type: application/sdp
                    Session-Expires: 900
                    Supported: 100rel, replaces, timer, precondition
                    Accept: application/sdp
                    Min-SE: 90
                    Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
                    P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel
                    Contact: $contactTel
                    """.toSipHeadersMap() + generateCallId() - "p-asserted-identity"
            // P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel
            // Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
            val msg =
                SipRequest(
                    SipMethod.INVITE,
                    to,
                    myHeaders,
                    sdp
                )
            setResponseCallback(msg.headers["call-id"]!![0]) { r: SipResponse ->
                var resp = r
                var cseq = resp.headers["cseq"]!![0]

                var rseqHandled = false
                // If we stopped our process to PRACK a response, start again processing it
                if (cseq.contains("PRACK")) {
                    resp = respInFlight!!
                    respInFlight = null
                    cseq = resp.headers["cseq"]!![0]
                    rseqHandled = true
                }

                if (cseq.contains("ACK")) return@setResponseCallback  false

                if (cseq.contains("INVITE") && (resp.statusCode == 200 || resp.statusCode == 202)) {
                    // TODO Send UI that call started
                    val msg2 =
                        SipRequest(
                            SipMethod.ACK,
                            to,
                            myHeaders - "content-type"
                        )
                    synchronized(socket.writer) { socket.writer.write(msg2.toByteArray()) }
                    callStarted.set(true)
                    Rlog.d(TAG, "Invite got SUCCESS")
                } else {
                    Rlog.d(TAG, "Invite got status ${resp.statusCode} = ${resp.statusString}")
                }

                if(resp.headers["rseq"]?.isNotEmpty() == true && !rseqHandled) {
                    prack(resp)
                    respInFlight = resp
                    return@setResponseCallback false
                }

                val isSdp = resp.headers["content-type"]?.get(0) == "application/sdp"
                val isPrecondition = resp.headers["require"]?.get(0)?.contains("precondition") == true

                if (!isSdp) return@setResponseCallback false

                val respSdp = resp.body.toString(Charsets.UTF_8).split("[\r\n]+".toRegex()).toList()

                fun sdpElement(command: String): String? {
                    val v = respSdp.firstOrNull { it.startsWith("$command=")} ?: return null
                    return v.substring(2)
                }
                val rtpRemotePort = sdpElement("m")!!.split(" ")[1]
                val rtpRemoteAddr = InetAddress.getByName(sdpElement("c")!!.split(" ")[2])
                currentCall = Call(
                    outgoing = true,
                    amrTrack = amrTrack,
                    amrTrackDesc = amrTrackDesc,
                    dtmfTrack = dtmfTrack,
                    dtmfTrackDesc = dtmfTrackDesc,
                    // Update from/to/call-id based on the response we got to include the remote tag
                    callHeaders = myHeaders - "require" - "content-type" + ("from" to resp.headers["from"]!!) + ("to" to resp.headers["to"]!!) + ("call-id" to resp.headers["call-id"]!!),
                    rtpRemoteAddr = rtpRemoteAddr,
                    rtpRemotePort = rtpRemotePort.toInt(),
                    rtpSocket = rtpSocket,
                    sdp = resp.body)

                // This isn't the answer to our INVITE, but to our later precondition UPDATE
                // TODO Actually check cseq
                if(resp.headers["cseq"]?.get(0)?.contains("UPDATE") == true) {
                    if(isSdp && resp.statusCode == 200) {
                        // Nothing to do here, we've already upgraded the call with the new SDP, everything's fine
                        return@setResponseCallback false
                    }
                }

                if(isPrecondition && resp.statusCode == 183) {
                    Rlog.d(TAG, "Handling precondition...")
                    val currLocal = respSdp.first { it.startsWith("a=curr:qos local")}
                    // No resource has been allocated at either side
                    val localNone = currLocal.contains("none")
                    Rlog.d(TAG, "precondition: Curr is $currLocal $localNone")
                    val currRemote = respSdp.first { it.startsWith("a=curr:qos remote")}
                    val remoteNone = currRemote.contains("none")

                    if (localNone) {
                        // "Allocating our local resource" and update the call
                        callDecodeThread()
                        callEncodeThread()

                        val newSdp = respSdp.map { line ->
                            if (line.startsWith("a=curr:qos local")) {
                                "a=curr:qos local sendrecv"
                            } else if (line.startsWith("a=des:qos mandatory local")) {
                                "a=des:qos mandatory local sendrecv"
                            } else {
                                line
                            }
                        }.joinToString("\r\n").toByteArray()

                        val msg2 =
                            SipRequest(
                                SipMethod.UPDATE,
                                to,
                                currentCall!!.callHeaders + ("content-type" to listOf("application/sdp")),
                                newSdp
                            )
                        Rlog.d(TAG, "Sending $msg2")
                        synchronized(socket.writer) { socket.writer.write(msg2.toByteArray()) }
                    }

                    return@setResponseCallback false
                }

                if(!isPrecondition && resp.statusCode == 183) {
                    callDecodeThread()
                    callEncodeThread()
                }

                   /* } else {
                        imsMediaManager.openSession(
                            rtpSocket, fakeRtcpSocket,
                            ImsMediaSession.SESSION_TYPE_AUDIO,
                            AudioConfig.Builder()
                                .setCodecType(AudioConfig.CODEC_AMR)
                                .setRxPayloadTypeNumber(amrTrack.toByte())
                                .setTxPayloadTypeNumber(amrTrack.toByte())
                                .setRemoteRtpAddress(InetSocketAddress(rtpRemoteAddr, rtpRemotePort.toInt()))
                                .setSamplingRateKHz(8)
                                .setAmrParams(AmrParams.Builder()
                                    .setOctetAligned(false)
                                    .setAmrMode(AmrParams.AMR_MODE_7)
                                    .build())
                                .setMediaDirection(RtpConfig.MEDIA_DIRECTION_SEND_RECEIVE)
                                .build(),
                            myExecutor,
                            object: AudioSessionCallback() {
                                override fun onOpenSessionSuccess(session: ImsMediaSession) {
                                    Rlog.d(TAG, "Opened session $session")
                                    currentCall = Call(
                                        amrTrack = amrTrack,
                                        amrTrackDesc = amrTrackDesc,
                                        dtmfTrack = dtmfTrack,
                                        dtmfTrackDesc = dtmfTrackDesc,
                                        callHeaders = myHeaders - "require" - "content-type" + "Supported: precondition, 100rel, replaces, timer".toSipHeadersMap(),
                                        rtpRemoteAddr = rtpRemoteAddr,
                                        rtpRemotePort = rtpRemotePort.toInt(),
                                        rtpSocket = rtpSocket,
                                        sdp = resp.body,
                                        imsMediaSession = session)
                                }

                                override fun onOpenSessionFailure(error: Int) {
                                    Rlog.d(TAG, "Failed to open session $error")
                                }
                                override fun onSessionClosed() {
                                    Rlog.d(TAG, "Session closed")
                                }
                            }
                        )
                    }*/
                false // Return true when we want to stop receiving messages for that call
            }
            Rlog.d(TAG, "Sending $msg")
            synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }
        }
    }

    fun callDecodeThread() {
        // Receiving thread
        thread {
            val minBufferSize = AudioTrack.getMinBufferSize(8000, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
            val audioTrack = AudioTrack(AudioManager.STREAM_VOICE_CALL, 8000, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT, minBufferSize, AudioTrack.MODE_STREAM)
            audioTrack.play()

            val decoder = MediaCodec.createDecoderByType("audio/3gpp")
            val mediaFormat = MediaFormat.createAudioFormat("audio/3gpp", 8000, 1)
            decoder.configure(mediaFormat, null, null, 0)
            decoder.start()

            while(true) {
                if(callStopped.get()) break
                val dgramBuf = ByteArray(2048)
                val dgram = DatagramPacket(dgramBuf, dgramBuf.size)
                currentCall!!.rtpSocket.receive(dgram)

                //TODO: Check RTP payload type

                val ft = (dgramBuf[13].toUByte().toUInt() shr 7) or ((dgramBuf[12].toUByte().toUInt() and (7).toUInt()) shl 1)
                Rlog.d(TAG, "Received RTP data is length ${dgram.length} ft is $ft")

                if(ft.toInt() != 7) continue

                // RTP header 12 byte
                // AMR in RTP header 10 bits
                // Packet size 32, FT=7
                val baOs = ByteArrayOutputStream()

                baOs.write( ft.toInt() shl 3)

                var m = 0
                // Warning: we should take good care counting the **bits** of the packet based on FT
                for(i in 13 until dgram.length ) {
                    // Take 6 bits left, 2 bits right
                    val left = (dgramBuf[i].toUByte().toUInt().toInt() and 0x3f)  shl 2
                    val right = (dgramBuf[i + 1 ].toUByte().toUInt().toInt() shr 6) and 0x3
                    m++
                    baOs.write(left or right)
                }
                Rlog.d(TAG, "Received RTP data of length ${dgram.length} $m")

                val inBufIndex = decoder.dequeueInputBuffer(-1)
                Rlog.d(TAG, "Got decoding input buffer $inBufIndex")
                val inBuf = decoder.getInputBuffer(inBufIndex)!!
                val data = baOs.toByteArray()
                inBuf.clear()
                inBuf.put(data)
                decoder.queueInputBuffer(inBufIndex, 0, data.size, 0, 0)

                //TODO: Support DTX (comfort noise frames that don't repeat)
                //TODO: Can we receive multiple outs per in?
                val outBufInfo = MediaCodec.BufferInfo()
                val outBufIndex = decoder.dequeueOutputBuffer(outBufInfo, 0)
                Rlog.d(TAG, "Got decoding output buffer $outBufIndex")
                if (outBufIndex >= 0) {
                    val outBuf = decoder.getOutputBuffer(outBufIndex)!!
                    audioTrack.write(outBuf, outBufInfo.size, AudioTrack.WRITE_BLOCKING)
                    decoder.releaseOutputBuffer(outBufIndex, false)
                }
            }
            audioTrack.stop()
            audioTrack.release()
            decoder.stop()
            decoder.release()
        }
    }

    fun extractDestinationFromContact(contact: String): String {
        val r = Regex(".*<(sip:[^>]*)>.*")
        return r.find(contact)!!.groups[1]!!.value
    }

    val callStopped = AtomicBoolean(false)
    val callStarted = AtomicBoolean(false)
    val updateReceived = AtomicBoolean(false)

    val prAckWaitLock = Object()
    var prAckWait = mutableSetOf<Int>()
    fun handleCall(request: SipRequest): Int {
        val contentType = request.headers["content-type"]!![0]
        if (contentType != "application/sdp") return 404
        callStopped.set(false)
        callStarted.set(false)

        val f = request.headers["from"]
        val r = Regex(".*(sip|tel):([^@]*).*")
        val m = r.find(f!![0]!!)!!.groups[2]!!.value
        Rlog.d(TAG, "Incoming call from $m")
        onIncomingCall?.invoke(Object(), m, mapOf("call-id" to request.headers["call-id"]!![0]))

        // We'll have three states:
        // - 100 Trying (this will be done by returning 100 in this function)
        // - 183 Session Progress network-wise we're ready to receive data
        // - 180 Ringing Notification's AudioTrack is playing, the user can hear its phone -- Note: Ringing doesn't give SDP
        // - 200 User has accepted the call

        val sdp = request.body.toString(Charsets.UTF_8).split("[\r\n]+".toRegex()).toList()
        Rlog.d(TAG, "Split SDP into $sdp")
        fun sdpElement(command: String): String? {
            val v = sdp.firstOrNull { it.startsWith("$command=")} ?: return null
            return v.substring(2)
        }
        val sdpConnectionData = sdpElement("c")
        val sdpOrigin = sdpElement("o")
        val sdpSessionName = sdpElement("s")
        val sdpTiming = sdpElement("t")
        val sdpBandwidth = sdpElement("b")
        val sdpMedia = sdpElement("m")

        Rlog.d(TAG, "Got sdpTiming $sdpTiming")

        if (sdpTiming != "0 0")
            Rlog.d(TAG, "Uh-oh, unknown timing mode")


        val rtpRemote = sdpConnectionData!!.split(" ")[2] //c=IN IP6 xxx
        val rtpRemoteAddr = InetAddress.getByName(rtpRemote)
        val rtpRemotePort = sdpMedia!!.split(" ")[1] //m=audio 30798 RTP/AVP 96 97 98 8 18 101 100 99

        val attributes = sdp.filter { it.startsWith("a=") }.map { it.substring(2)}

        fun lookTrackMatching(codec: String, additional: String = "", notAdditional: String = ""): Pair<Int,String>? {
            //TODO: also match on fmtp
            val maps = attributes.filter { it.startsWith("rtpmap") && it.contains(codec) }
            val matches = maps.map { m ->
                val track = m.split("[: ]+".toRegex())[1].toInt()
                val desc = m
                Pair(track, desc)
            }
            Rlog.d(TAG, "Matching $codec, got $matches")
            val matches2 = if(matches.size > 1) {
                matches.sortedBy { m ->
                    val fmtp = attributes.filter { it.startsWith("fmtp:${m.first}") }[0]
                    Rlog.d(TAG, "Matching $codec, for match $m got fmtp $fmtp")
                    if(fmtp.contains(additional))
                        0
                    else if (notAdditional.isNotEmpty() && !fmtp.contains(notAdditional))
                        1
                    else
                        2
                }
            } else {
                matches
            }
            Rlog.d(TAG, "Matching2 $codec, got $matches2")
            return matches2.firstOrNull()
        }

        fun trackRequirements(track: Int): String? {
            return attributes.firstOrNull() { it.startsWith("fmtp:$track") }
        }

        // Look for an AMR/8000 mode
        // TODO: Select which one? SFR has two, one with mode-set=7 one without it. This would require reading the fmtp lines
        val (amrTrack, amrTrackDesc) = lookTrackMatching("AMR/8000", "octet-align=0", "octet-align=1")!!
        val amrTrackRequirements = trackRequirements(amrTrack)

        // Look for a DTMF track, use the 8000Hz-based one to match AMR timestamps
        val (dtmfTrack, dtmfTrackDesc) = lookTrackMatching("telephone-event/8000")!!

        val allTracks = listOf(amrTrack, dtmfTrack).sorted()

        thread {
            // Need to sleep a bit so that our 100 Trying is sent first. Kinda weird.
            Thread.sleep(500)
            val rtpSocket = DatagramSocket(0, localAddr)
            network.bindSocket(rtpSocket)
            rtpSocket.connect(rtpRemoteAddr, rtpRemotePort.toInt())

            val local = "[${socket.localAddr.hostAddress}]:${serverSocket.localPort}"
            val sipInstance = "<urn:gsma:imei:${imei.substring(0,8)}-${imei.substring(8,14)}-0>"
            val contactTel =
                """<sip:$myTel@$local;transport=tcp>;expires=600000;+sip.instance="$sipInstance";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;audio"""
            val mySeqCounter = reliableSequenceCounter++
            val ipType = if(socket.localAddr is Inet6Address) "IP6" else "IP4"
            val mySdp = """
v=0
o=- 1 2 IN $ipType ${socket.localAddr.hostAddress}
s=phh voice call
c=IN $ipType ${socket.localAddr.hostAddress}
b=AS:38
b=RS:0
b=RR:0
t=0 0
m=audio ${rtpSocket.localPort} RTP/AVP ${allTracks.joinToString(" ")}
b=AS:38
b=RS:0
b=RR:0
a=$amrTrackDesc
a=ptime:20
a=maxptime:240
a=$dtmfTrackDesc
a=fmtp:$amrTrack mode-set=7;octet-align=0;max-red=0
a=fmtp:$dtmfTrack 0-15
a=curr:qos local none
a=curr:qos remote none
a=des:qos mandatory local sendrecv
a=des:qos mandatory remote sendrecv
a=conf:qos remote sendrecv
a=sendrecv
                       """.trim().toByteArray()

            val myHeaders = commonHeaders + //Require: precondition
                """
                        Contact: $contactTel
                        Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, INFO, MESSAGE, PRACK, OPTIONS
                        Content-Type: application/sdp
                        Require: 100rel, precondition
                        RSeq: $mySeqCounter
                        P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=20810b8c49752501
                        """.toSipHeadersMap() +
                            request.headers.filter { (k, _) -> k in listOf("cseq", "via", "from", "to", "call-id") } -
                "route" - "security-verify"

            currentCall = Call(
                outgoing = false,
                amrTrack = amrTrack,
                amrTrackDesc = amrTrackDesc,
                dtmfTrack = dtmfTrack,
                dtmfTrackDesc = dtmfTrackDesc,
                callHeaders = myHeaders - "require" - "content-type" + "Supported: 100rel, replaces, timer".toSipHeadersMap(),
                rtpRemoteAddr = rtpRemoteAddr,
                rtpRemotePort = rtpRemotePort.toInt(),
                rtpSocket =  rtpSocket,
                sdp = mySdp
            )

            if(false) {
                val fakeRtcpSocket = DatagramSocket(0, localAddr) //useless but annoying ImsMediaManager
                imsMediaManager.openSession(
                    rtpSocket, fakeRtcpSocket,
                    ImsMediaSession.SESSION_TYPE_AUDIO,
                    AudioConfig.Builder()
                        .setCodecType(AudioConfig.CODEC_AMR)
                        .setRxPayloadTypeNumber(amrTrack.toByte())
                        .setTxPayloadTypeNumber(amrTrack.toByte())
                        .setRemoteRtpAddress(
                            InetSocketAddress(
                                rtpRemoteAddr,
                                rtpRemotePort.toInt()
                            )
                        )
                        .setSamplingRateKHz(8)
                        .setAmrParams(
                            AmrParams.Builder()
                                .setOctetAligned(false)
                                .setAmrMode(AmrParams.AMR_MODE_7)
                                .build()
                        )
                        .setMediaDirection(RtpConfig.MEDIA_DIRECTION_SEND_RECEIVE)
                        .build(),
                    myExecutor,
                    object: AudioSessionCallback() {
                        override fun onOpenSessionSuccess(session: ImsMediaSession) {
                            Rlog.d(TAG, "Opened session $session")
                            currentCall = Call(
                                outgoing = false,
                                amrTrack = amrTrack,
                                amrTrackDesc = amrTrackDesc,
                                dtmfTrack = dtmfTrack,
                                dtmfTrackDesc = dtmfTrackDesc,
                                callHeaders = myHeaders - "require" - "content-type" + "Supported: 100rel, replaces, timer".toSipHeadersMap(),
                                rtpRemoteAddr = rtpRemoteAddr,
                                rtpRemotePort = rtpRemotePort.toInt(),
                                rtpSocket = rtpSocket,
                                sdp = mySdp,
                                imsMediaSession = session)
                        }

                        override fun onOpenSessionFailure(error: Int) {
                            Rlog.d(TAG, "Failed to open session $error")
                        }
                        override fun onSessionClosed() {
                            Rlog.d(TAG, "Session closed")
                        }
                    }
                )
            } else {
                callDecodeThread()
                callEncodeThread()
            }


            synchronized(prAckWaitLock) {
                prAckWait += mySeqCounter
            }
            val msg =
                SipResponse(
                    statusCode = 183,
                    statusString = "Session Progress",
                    headersParam = myHeaders,
                    body = mySdp
                )
            Rlog.d(TAG, "Sending $msg")
            synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }
            waitPrack(mySeqCounter)

            /*val myHeaders2 = myHeaders - "rseq" - "content-type" - "require"
            val msg2 =
                SipResponse(
                    statusCode = 180,
                    statusString = "Ringing",
                    headersParam = myHeaders2
                )
            Rlog.d(TAG, "Sending $msg2")
            synchronized(socket.writer) { socket.writer.write(msg2.toByteArray()) }*/


        }
        return 100
    }

    fun handleSms(request: SipRequest): Int {
        val sms = request.body.SipSmsDecode()
        if (sms == null) {
            Rlog.w(TAG, "Could not decode sms pdu")
            return 500
        }
        Rlog.d(TAG, "Decoded SMS type ${sms.type}, ${sms.pdu?.toString()}")
        when (sms.type) {
            SmsType.RP_DATA_FROM_NETWORK -> {
                val receivedCb = try { onSmsReceived } catch(t: Throwable) { Rlog.d(TAG, "Failed sending SMS to framework", t); null}
                if (receivedCb == null) {
                    Rlog.d(TAG, "No onSmsReceived callback!")
                    return 500
                }

                val token = smsLock.withLock { smsToken++ }
                val dest =
                    request.headers["from"]!![0]
                        .getParams()
                        .component1()
                        .trimStart('<')
                        .trimEnd('>')
                val callId = request.headers["call-id"]!![0]
                val cseq = request.headers["cseq"]!![0]
                smsHeadersMap[token] = smsHeaders(dest, callId, cseq)
                receivedCb(token, "3gpp", sms.pdu!!)
            }
            SmsType.RP_ACK_FROM_NETWORK -> {
                try {
                    onSmsStatusReportReceived?.invoke(sms.ref.toInt(), "3gpp", ByteArray(2))
                } catch(t: Throwable) {
                    Rlog.d(TAG, "Failed sending SMS ACK to framework", t)
                }
            }
            else -> return 500
        }
        return 200
    }

    fun sendSms(
        smsSmsc: String?,
        pdu: ByteArray,
        ref: Int,
        successCb: (() -> Unit),
        failCb: (() -> Unit)
    ) {
        val decodableSmsc = try {
            PhoneNumberUtils.numberToCalledPartyBCD(smsSmsc, PhoneNumberUtils.BCD_EXTENDED_TYPE_CALLED_PARTY); true
        } catch (t:Throwable) { false }

        // make ref up?
        val smsc =
            if (smsSmsc != null && decodableSmsc) smsSmsc
            else {
                val smsManager =
                    ctxt.getSystemService(SmsManager::class.java).createForSubscriptionId(subId)
                val smscStr = smsManager.smscAddress
                val smscMatchRegex = Regex("([0-9]+)")
                Rlog.d(TAG, "Got smsc $smscStr, match ${smscMatchRegex.find(smscStr!!)}")
                smscMatchRegex.find(smscStr!!)!!.groupValues[1]
            }
        val data = SipSmsEncodeSms(ref.toByte(), "+$smsc", pdu)
        Rlog.d(TAG, "sending sms ${data.toHex()} to smsc $smsc")

        val msg =
            SipRequest(
                SipMethod.MESSAGE,
                "sip:+$smsc@$realm",
                commonHeaders +
                    """
                    From: <$mySip>
                    To: <sip:+$smsc@$realm;user=phone>
                    P-Preferred-Identity: <$mySip>
                    P-Asserted-Identity: <$mySip>
                    Expires: 600000
                    Content-Type: application/vnd.3gpp.sms
                    Supported: sec-agree
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: MESSAGE
                    """.toSipHeadersMap(),
                data
            )
        setResponseCallback(
            msg.headers["call-id"]!![0],
            { resp: SipResponse ->
                if (resp.statusCode == 200 || resp.statusCode == 202) {
                    successCb()
                } else {
                    failCb()
                }
                true
            }
        )
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }
    }

    fun sendSmsAck(token: Int, ref: Int, error: Boolean): Unit {
        Rlog.d(TAG, "sending sms ack")
        val body = SipSmsEncodeAck(ref.toByte())
        val headers = smsHeadersMap.remove(token)
        if (headers == null) {
            // XXX return error?
            return
        }
        // do not send ack on error
        // Should we send an error report?
        if (error) {
            return
        }
        val msg =
            SipRequest(
                SipMethod.MESSAGE,
                headers.dest,
                commonHeaders +
                    """
                    Cseq: ${headers.cseq}
                    In-Reply-To: ${headers.callId}
                    Content-Type: application/vnd.3gpp.sms
                    Proxy-Require: sec-agree
                    Require: sec-agree
                    Allow: MESSAGE
                    Supported: path, gruu, sec-agree
                    Request-Disposition: no-fork
                    Accept-Contact: *;+g.3gpp.smsip
                    """.toSipHeadersMap(),
                body
            )
        // ignore response
        setResponseCallback(msg.headers["call-id"]!![0], { true })
        Rlog.d(TAG, "Sending $msg")
        synchronized(socket.writer) { socket.writer.write(msg.toByteArray()) }
    }
}
