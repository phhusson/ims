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
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import java.io.OutputStream
import java.net.InetAddress
import java.net.SocketException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

private data class smsHeaders(
    val dest: String,
    val callId: String,
    val cseq: String,
)

class SipHandler(val ctxt: Context) {
    companion object {
        private const val TAG = "PHH SipHandler"
    }

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

    private var registerCounter = 1
    private var registerHeaders =
        """
        From: <sip:$user>
        To: <sip:$user>
        Call-ID: ${randomBytes(12).toHex()}
        """.toSipHeadersMap()
    private var commonHeaders = "".toSipHeadersMap()
    private var contact = ""
    private var mySip = ""

    // too many lateinit, bad separation?
    lateinit private var localAddr: InetAddress
    lateinit private var pcscfAddr: InetAddress

    lateinit private var clientSpiC: IpSecManager.SecurityParameterIndex
    lateinit private var clientSpiS: IpSecManager.SecurityParameterIndex
    lateinit private var serverSpiC: IpSecManager.SecurityParameterIndex
    lateinit private var serverSpiS: IpSecManager.SecurityParameterIndex

    lateinit private var network: Network

    lateinit private var plainSocket: SipConnectionTcp
    lateinit private var socket: SipConnectionTcp
    lateinit private var serverSocket: SipConnectionTcpServer

    private val cbLock = ReentrantLock()
    private var requestCallbacks: Map<SipMethod, ((SipRequest) -> Int)> = mapOf()
    private var responseCallbacks: Map<String, ((SipResponse) -> Boolean)> = mapOf()
    private var imsReady = false
    var imsReadyCallback: (() -> Unit)? = null
    var imsFailureCallback: (() -> Unit)? = null
    var onSmsReceived: ((Int, String, ByteArray) -> Unit)? = null
    var onSmsStatusReportReceived: ((Int, String, ByteArray) -> Unit)? = null
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
        Rlog.d(TAG, "Received message $msg")
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
        val reply =
            SipResponse(
                statusCode = status,
                statusString = if (status == 200) "OK" else "ERROR",
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

    fun connect() {
        Rlog.d(TAG, "Trying to connect to SIP server")
        val lp = connectivityManager.getLinkProperties(network)
        val pcscfs = lp!!.javaClass.getMethod("getPcscfServers").invoke(lp) as List<InetAddress>
        if (pcscfs.size == 0) {
            Rlog.w(TAG, "Had no Pcscf Sever defined, aborting")
            imsFailureCallback?.invoke()
            return
        }
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
                .filter { supported_ealg.contains(it.component2()["ealg"]) }
                .filter { supported_alg.contains(it.component2()["alg"]) }
                .sortedByDescending { it.component2()["q"]?.toFloat() ?: 0.toFloat() }[0]
        require(securityServerType == "ipsec-3gpp")

        val portS = securityServerParams["port-s"]!!.toInt()
        // spi string is 32 bit unsigned, but ipSecManager wants an int...
        val spiS = securityServerParams["spi-s"]!!.toUInt().toInt()
        serverSpiS = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiS)

        // val portC = securityServerParams["port-c"]!!.toInt()
        val spiC = securityServerParams["spi-c"]!!.toUInt().toInt()
        serverSpiC = ipSecManager.allocateSecurityParameterIndex(pcscfAddr, spiC)

        val ealg = securityServerParams["ealg"]
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

        socket.enableIpsec(ipSecBuilder, ipSecManager, clientSpiC, serverSpiS)
        serverSocket.enableIpsec(ipSecBuilder, ipSecManager, clientSpiS, serverSpiC)
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
    }

    fun getVolteNetwork() {
        // TODO add something similar for VoWifi ipsec tunnel?
        Rlog.d(TAG, "Requesting IMS network")
        connectivityManager.registerNetworkCallback(
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .setNetworkSpecifier(subId.toString())
                .addCapability(NetworkCapabilities.NET_CAPABILITY_IMS)
                .build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(_network: Network) {
                    Rlog.d(TAG, "Got IMS network.")
                    network = _network
                    connect()
                }
            }
        )
    }

    fun updateCommonHeaders(socket: SipConnectionTcp) {
        val local = "[${socket.localAddr.hostAddress}]:${socket.localPort}"
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
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=${clientSpiC.spi};spi-s=${clientSpiS.spi};port-c=${socket.localPort};port-s=${serverSocket.localPort};ealg=${ealg};alg=${alg}"
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

        val route =
            (response.headers.getOrDefault("service-route", emptyList()) +
                    response.headers.getOrDefault("path", emptyList()))
                .toSet() // remove duplicates
                .toList()

        val associatedUri =
            response.headers["p-associated-uri"]!!.map { it.trimStart('<').trimEnd('>').split(':') }
        mySip = "sip:" + associatedUri.first { it[0] == "sip" }[1]
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
        val msg =
            SipRequest(
                SipMethod.SUBSCRIBE,
                "$mySip",
                commonHeaders +
                    """
                    Contact: $contact
                    P-Preferred-Identity: <$mySip>
                    Event: reg
                    Expires: 600000
                    Supported: sec-agree
                    Require: sec-agree
                    Proxy-Require: sec-agree
                    Allow: INVITE, ACK, CANCEL, BYE, UPDATE, REFER, NOTIFY, MESSAGE, PRACK, OPTIONS
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

    fun handleSms(request: SipRequest): Int {
        val sms = request.body.SipSmsDecode()
        if (sms == null) {
            Rlog.w(TAG, "Could not decode sms pdu")
            return 500
        }
        Rlog.d(TAG, "Decoded SMS type ${sms.type}, ${sms.pdu?.toString()}")
        when (sms.type) {
            SmsType.RP_DATA_FROM_NETWORK -> {
                val receivedCb = onSmsReceived
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
                onSmsStatusReportReceived?.invoke(sms.ref.toInt(), "3gpp", ByteArray(2))
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
        // make ref up?
        val smsc =
            if (smsSmsc != null) smsSmsc
            else {
                val smsManager =
                    ctxt.getSystemService(SmsManager::class.java).createForSubscriptionId(subId)
                val smscStr = smsManager.smscAddress
                val smscMatchRegex = Regex("([0-9]+)")
                smscMatchRegex.find(smscStr!!)!!.groupValues[1]
            }
        val data = SipSmsEncodeSms(ref.toByte(), "+$smsc", pdu)
        Rlog.d(TAG, "sending sms ${data.toHex()} to smsc $smsc")
        /* XXX test
        val t = SmsMessage.getSubmitPdu(smsc, "xxxxxxxxxxx", "hello", false)
        val tpdu = t.encodedMessage
        val headerSize = 3
        val scSize = t.encodedScAddress?.size ?: 0
        val v = ByteArray(tpdu.size + headerSize + scSize + 1)
        v[0] = 0
        v[1] = 0
        v[2] = 0
        if (t.encodedScAddress != null) System.arraycopy(t.encodedScAddress, 0, v, 3, scSize)
        v[3 + scSize] = tpdu.size.toByte()
        System.arraycopy(tpdu, 0, v, 3 + scSize + 1, tpdu.size)
        Rlog.d(TAG, "phh would have sent ${v.toHex()}")
        */
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
