package me.phh.sip

import android.net.IpSecManager
import android.net.IpSecTransform
import android.net.Network
import java.io.FileDescriptor
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/* wrapper around sockets + establish ipsec tunnel given ipsec helpers */

class SipConnectionTcp(
    val network: Network,
    val remoteAddr: InetAddress,
    val _localAddr: InetAddress? = null,
    val _localPort: Int = 0
) {
    val socket: Socket
    /* redefine public localAddr/port for when not specified in argument */
    var localAddr: InetAddress
    var localPort: Int
    var remotePort: Int = 0
    lateinit var writer: OutputStream
    lateinit var reader: SipReader
    var connected = false

    init {
        socket = network.socketFactory.createSocket()
        if (_localAddr != null) {
            socket.bind(InetSocketAddress(_localAddr, _localPort))
        }
        localAddr = socket.localAddress
        localPort = socket.localPort
    }

    fun connect(_remotePort: Int) {
        remotePort = _remotePort
        socket.connect(InetSocketAddress(remoteAddr, remotePort))
        if (_localAddr == null) {
            // localAddr/Port only valid after connect if no explicit bind
            localAddr = socket.localAddress
            localPort = socket.localPort
        }
        writer = socket.getOutputStream()
        reader = socket.getInputStream().sipReader()
        connected = true
    }

    fun close() {
        socket.close()
    }

    fun enableIpsec(
        ipSecBuilder: IpSecTransform.Builder,
        ipSecManager: IpSecManager,
        clientSpiC: IpSecManager.SecurityParameterIndex,
        serverSpiS: IpSecManager.SecurityParameterIndex
    ) {
        // Can only do this before connecting?
        check(!connected)
        val inTransform = ipSecBuilder.buildTransportModeTransform(remoteAddr, clientSpiC)
        ipSecManager.applyTransportModeTransform(socket, IpSecManager.DIRECTION_IN, inTransform)
        val outTransform = ipSecBuilder.buildTransportModeTransform(localAddr, serverSpiS)
        ipSecManager.applyTransportModeTransform(socket, IpSecManager.DIRECTION_OUT, outTransform)
    }
}

class SipConnectionTcpServer(
    val network: Network,
    val remoteAddr: InetAddress,
    val localAddr: InetAddress,
    val localPort: Int
) {
    val serverSocket: ServerSocket
    val serverSocketFd: FileDescriptor

    init {
        serverSocket = ServerSocket()
        serverSocket.bind(InetSocketAddress(localAddr, localPort))
        serverSocketFd =
            serverSocket.javaClass.getMethod("getFileDescriptor\$").invoke(serverSocket)
                as FileDescriptor
        network.bindSocket(serverSocketFd)
    }

    fun accept(): Pair<SipReader, OutputStream> {
        val client = serverSocket.accept()
        return Pair(client.getInputStream().sipReader(), client.getOutputStream())
    }

    fun enableIpsec(
        ipSecBuilder: IpSecTransform.Builder,
        ipSecManager: IpSecManager,
        clientSpiS: IpSecManager.SecurityParameterIndex,
        serverSpiC: IpSecManager.SecurityParameterIndex
    ) {
        val inTransform = ipSecBuilder.buildTransportModeTransform(remoteAddr, clientSpiS)
        ipSecManager.applyTransportModeTransform(
            serverSocketFd,
            IpSecManager.DIRECTION_IN,
            inTransform
        )
        val outTransform = ipSecBuilder.buildTransportModeTransform(localAddr, serverSpiC)
        ipSecManager.applyTransportModeTransform(
            serverSocketFd,
            IpSecManager.DIRECTION_OUT,
            outTransform
        )
    }
}

/*
class SipConnectionUdp(val params: SipConnectionParams): SipConnection() {
    // UDP "connection"
    // poll thread: just keep reading messages
    // XXX resend if no reply within timeout? probably SipManager level...
    val socket: DatagramSocket
    init {
        socket = DatagramSocket(params.localPort, params.localAddr)
        params.network.bindSocket(socket)
        socket.connect(params.remoteAddr, params.remotePort)

        // XXX ipSecManager setup, can combine both TCP transforms on same socket here

        thread {
            // XXX packet size
            val packetData = ByteArray(4096)
            val packet = DatagramPacket(packetData, packetData.size)
            var reader: SipReader? = null
            while (true) {
                // There could be multiple message in a single datagram
                // so keep reader around until no message can be read
                // Invalid data still returns a 'SpiCommonMessage' that
                // should error in callback.
                if (reader == null) {
                    socket.receive(packet)
                    val buffer = packet.getData()
                    reader = buffer.inputStream().sipReader()
                }
                val message = reader.parseMessage()
                if (message == null) {
                    reader = null
                    continue
                }
                if (!params.callback(message)) {
                    // callback failure means unexpected data received,
                    // abort thread.
                    // XXX signal this to SipManager so it can reconnect
                    socket.close()
                    break
                }
            }
        }
    }
}
*/
