//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.net.IpSecManager
import android.net.IpSecTransform
import android.net.Network
import android.telephony.Rlog
import java.io.FileDescriptor
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.StandardProtocolFamily
import java.nio.channels.Channel
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectableChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.spi.SelectorProvider

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
    fun getChannel(): SelectableChannel
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

    override fun getChannel(): SelectableChannel {
        return socket.channel
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

    fun getChannel(): SelectableChannel {
        return serverSocket.channel
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
        val channel = DatagramChannel.open(if(remoteAddr is Inet6Address) StandardProtocolFamily.INET6 else StandardProtocolFamily.INET)
        if (_localAddr != null) {
            channel.bind(InetSocketAddress(_localAddr, _localPort))
        }
        socket = channel.socket()
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
            val currentDgram = DatagramPacket(ByteArray(128*1024), 128*1024)
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

    override fun getChannel(): SelectableChannel {
        return socket.channel
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
        val channel = DatagramChannel.open(if(remoteAddr is Inet6Address) StandardProtocolFamily.INET6 else StandardProtocolFamily.INET)
        channel.bind(InetSocketAddress(localAddr, localPort))
        socket = channel.socket()
        network.bindSocket(socket)
        socketFd =
            socket.javaClass.getMethod("getFileDescriptor\$").invoke(socket)
                as FileDescriptor
    }

    fun gReader(): SipReader {
        return object: InputStream() {
            val currentDgram = DatagramPacket(ByteArray(128*1024), 128*1024)
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

    fun getChannel(): SelectableChannel {
        return socket.channel
    }
}

fun select(channels: List<SelectableChannel>): Int {
    var returnValue = -1
    Selector.open().use { selector ->
        for (channel in channels) {
            channel.configureBlocking(false)
            channel.register(selector, SelectionKey.OP_READ)
        }

        val nSelectedKeys = selector.select()
        for (key in selector.selectedKeys()) {
            if (key.isReadable) {
                val index = channels.indexOf(key.channel())
                if (index != -1) {
                    Rlog.e("PHH", "When selecting got result $index")
                    returnValue = index
                    break
                }
            }
        }
    }
    for (channel in channels) {
        channel.configureBlocking(true)
    }

    return returnValue
}
