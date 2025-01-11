//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.net.IpSecManager
import android.net.IpSecTransform
import android.net.Network
import java.io.FileDescriptor
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/* wrapper around sockets + establish ipsec tunnel given ipsec helpers */
interface SipConnection {
    fun close()
    fun enableIpsec(
        ipSecBuilder: IpSecTransform.Builder,
        ipSecManager: IpSecManager,
        clientSpiC: IpSecManager.SecurityParameterIndex,
        serverSpiS: IpSecManager.SecurityParameterIndex
    )
    fun gLocalAddr(): InetAddress
    fun connect(remotePort: Int)
    fun gWriter(): OutputStream
    fun gReader(): SipReader
    fun gLocalPort(): Int
}
class SipConnectionTcp(
    val network: Network,
    val remoteAddr: InetAddress,
    val _localAddr: InetAddress? = null,
    val _localPort: Int = 0
) : SipConnection {
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

    override fun connect(_remotePort: Int) {
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

    override fun gWriter(): OutputStream {
        return writer
    }

    override fun gReader(): SipReader {
        return reader
    }

    override fun gLocalPort(): Int {
        return localPort
    }

    override fun close() {
        socket.close()
    }

    override fun enableIpsec(
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

    override fun gLocalAddr(): InetAddress {
        return localAddr
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
    val _localAddr: InetAddress? = null,
    val _localPort: Int = 0,
) : SipConnection {
    val socket: DatagramSocket
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
        if (_localAddr != null) {
            socket = DatagramSocket(_localPort, _localAddr)
        } else {
            socket = DatagramSocket()
        }
        network.bindSocket(socket)

        localAddr = socket.localAddress
        localPort = socket.localPort
    }

    override fun connect(_remotePort: Int) {
        remotePort = _remotePort
        // Note: DO NOT connect, because the answers might come back from a different IP than where we sent to
        //socket.connect(InetSocketAddress(remoteAddr, remotePort))
        if (_localAddr == null) {
            // localAddr/Port only valid after connect if no explicit bind
            localAddr = socket.localAddress
            localPort = socket.localPort
        }
        writer = object: OutputStream() {
            override fun write(p0: Int) {
                socket.send(DatagramPacket(byteArrayOf(p0.toByte()), 1, remoteAddr, remotePort))
            }
            override fun write(p0: ByteArray) {
                socket.send(DatagramPacket(p0, p0.size, remoteAddr, remotePort))
            }
        }
        reader = object: InputStream() {
            val currentDgram = DatagramPacket(ByteArray(1500), 1500)
            var currentPosition = 0
            var currentSize = 0
            override fun read(): Int {
                if (currentPosition >= currentSize) {
                    socket.receive(currentDgram)
                    currentPosition = 0
                    currentSize = currentDgram.length
                }
                return currentDgram.data[currentPosition++].toInt()
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (currentPosition >= currentSize) {
                    socket.receive(currentDgram)
                    currentPosition = 0
                    currentSize = currentDgram.length
                }
                val toRead = minOf(len, currentSize - currentPosition)
                currentDgram.data.copyInto(b, off, currentPosition, currentPosition + toRead)
                currentPosition += toRead
                return toRead
            }
        }.sipReader()
        connected = true
    }

    override fun gWriter(): OutputStream {
        return writer
    }

    override fun gReader(): SipReader {
        return reader
    }

    override fun gLocalPort(): Int {
        return localPort
    }

    override fun close() {
        socket.close()
    }

    override fun enableIpsec(
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

    override fun gLocalAddr(): InetAddress {
        return localAddr
    }
}

class SipConnectionUdpServer(
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

    fun gReader(): SipReader {
        return object: InputStream() {
            val currentDgram = DatagramPacket(ByteArray(1500), 1500)
            var currentPosition = 0
            var currentSize = 0
            override fun read(): Int {
                if (currentPosition >= currentSize) {
                    socket.receive(currentDgram)
                    currentPosition = 0
                    currentSize = currentDgram.length
                }
                return currentDgram.data[currentPosition++].toInt()
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (currentPosition >= currentSize) {
                    socket.receive(currentDgram)
                    currentPosition = 0
                    currentSize = currentDgram.length
                }
                val toRead = minOf(len, currentSize - currentPosition)
                currentDgram.data.copyInto(b, off, currentPosition, currentPosition + toRead)
                currentPosition += toRead
                return toRead
            }
        }.sipReader()
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
