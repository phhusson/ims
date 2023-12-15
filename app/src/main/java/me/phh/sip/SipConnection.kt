//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.net.IpSecManager
import android.net.IpSecTransform
import android.net.Network
import java.io.FileDescriptor
import java.io.OutputStream
import java.net.DatagramSocket
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
    // we need to keep the transform around or the ipsec transform
    // gets destroyed while still in use
    lateinit var inTransform: IpSecTransform
    lateinit var outTransform: IpSecTransform
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
        inTransform = ipSecBuilder.buildTransportModeTransform(remoteAddr, clientSpiC)
        ipSecManager.applyTransportModeTransform(socket, IpSecManager.DIRECTION_IN, inTransform)
        outTransform = ipSecBuilder.buildTransportModeTransform(localAddr, serverSpiS)
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
    lateinit var inTransform: IpSecTransform
    lateinit var outTransform: IpSecTransform

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
        ipSecManager: IpSecManager,
        inTransform: IpSecTransform,
        outTransform: IpSecTransform
    ) {
        this.inTransform = inTransform
        ipSecManager.applyTransportModeTransform(
            serverSocketFd,
            IpSecManager.DIRECTION_IN,
            inTransform
        )
        this.outTransform = outTransform
        ipSecManager.applyTransportModeTransform(
            serverSocketFd,
            IpSecManager.DIRECTION_OUT,
            outTransform
        )
    }
}

class SipConnectionUdp(
    val network: Network,
    val remoteAddr: InetAddress,
    val localAddr: InetAddress,
    val localPort: Int) {

    val socket: DatagramSocket
    val socketFd : FileDescriptor
    lateinit var inTransform: IpSecTransform
    lateinit var outTransform: IpSecTransform
    init {
        socket = DatagramSocket(localPort, localAddr)
        network.bindSocket(socket)
        socketFd =
            socket.javaClass.getMethod("getFileDescriptor\$").invoke(socket)
                as FileDescriptor
    }

    fun enableIpsec(
        ipSecManager: IpSecManager,
        inTransform: IpSecTransform,
        outTransform: IpSecTransform
    ) {
        this.inTransform = inTransform
        ipSecManager.applyTransportModeTransform(
            socketFd,
            IpSecManager.DIRECTION_IN,
            inTransform
        )
        this.outTransform = outTransform
        ipSecManager.applyTransportModeTransform(
            socketFd,
            IpSecManager.DIRECTION_OUT,
            outTransform
        )
    }
}
