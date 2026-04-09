package com.notcvnt.rknhardering.network

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean

internal class FakeDnsServer(
    private val records: Map<String, Record>,
) : Closeable {
    data class Record(
        val ipv4: String? = null,
        val ipv6: String? = null,
        val nxdomain: Boolean = false,
    )

    private val running = AtomicBoolean(true)
    private val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
    private val worker = Thread(::runLoop, "fake-dns-server").apply {
        isDaemon = true
        start()
    }

    val port: Int
        get() = socket.localPort

    override fun close() {
        running.set(false)
        socket.close()
        worker.join(1_000)
    }

    private fun runLoop() {
        val buffer = ByteArray(1500)
        while (running.get()) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
                val response = buildResponse(packet.data.copyOf(packet.length))
                socket.send(DatagramPacket(response, response.size, packet.address, packet.port))
            } catch (_: SocketException) {
                if (!running.get()) return
            }
        }
    }

    private fun buildResponse(request: ByteArray): ByteArray {
        val query = parseQuery(request)
        val record = records[query.hostname]

        return when {
            record == null || record.nxdomain -> buildHeader(
                id = query.id,
                flags = 0x8183,
                question = query.question,
                answer = null,
            )
            query.qtype == TYPE_A && record.ipv4 != null -> buildHeader(
                id = query.id,
                flags = 0x8180,
                question = query.question,
                answer = Answer(TYPE_A, InetAddress.getByName(record.ipv4).address),
            )
            query.qtype == TYPE_AAAA && record.ipv6 != null -> buildHeader(
                id = query.id,
                flags = 0x8180,
                question = query.question,
                answer = Answer(TYPE_AAAA, InetAddress.getByName(record.ipv6).address),
            )
            else -> buildHeader(
                id = query.id,
                flags = 0x8180,
                question = query.question,
                answer = null,
            )
        }
    }

    private fun parseQuery(request: ByteArray): Query {
        val id = readUnsignedShort(request, 0)
        var offset = 12
        val labels = mutableListOf<String>()
        while (offset < request.size) {
            val length = request[offset].toInt() and 0xFF
            if (length == 0) {
                offset += 1
                break
            }
            val label = request.copyOfRange(offset + 1, offset + 1 + length).toString(Charsets.UTF_8)
            labels += label
            offset += 1 + length
        }
        val qtype = readUnsignedShort(request, offset)
        val questionEnd = offset + 4
        return Query(
            id = id,
            hostname = labels.joinToString("."),
            qtype = qtype,
            question = request.copyOfRange(12, questionEnd),
        )
    }

    private fun buildHeader(
        id: Int,
        flags: Int,
        question: ByteArray,
        answer: Answer?,
    ): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeShort(id)
            stream.writeShort(flags)
            stream.writeShort(1)
            stream.writeShort(if (answer != null) 1 else 0)
            stream.writeShort(0)
            stream.writeShort(0)
            stream.write(question)
            if (answer != null) {
                stream.writeShort(0xC00C)
                stream.writeShort(answer.type)
                stream.writeShort(1)
                stream.writeInt(60)
                stream.writeShort(answer.payload.size)
                stream.write(answer.payload)
            }
        }
        return output.toByteArray()
    }

    private fun readUnsignedShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private data class Query(
        val id: Int,
        val hostname: String,
        val qtype: Int,
        val question: ByteArray,
    )

    private data class Answer(
        val type: Int,
        val payload: ByteArray,
    )

    private companion object {
        private const val TYPE_A = 1
        private const val TYPE_AAAA = 28
    }
}
