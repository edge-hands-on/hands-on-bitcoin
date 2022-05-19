package com.example.bitcoinhandson

import com.example.bitcoinhandson.Utils.Companion.decodeP2WPKHAddress
import com.example.bitcoinhandson.Utils.Companion.doubleSha256
import com.example.bitcoinhandson.Utils.Companion.eightBytesLittleEndian
import com.example.bitcoinhandson.Utils.Companion.fourBytesLittleEndian
import com.example.bitcoinhandson.Utils.Companion.oneByte
import java.nio.ByteBuffer
import java.nio.ByteOrder.LITTLE_ENDIAN

class Transaction private constructor(
    val network: Network,
    private val txInList: List<TxIn>,
    private val txOutList: List<TxOut>
) {
    companion object {
        private val VERSION = fourBytesLittleEndian(1)
        private val SEQUENCE = "ffffffff".fromHexString()
        private val LOCKTIME = fourBytesLittleEndian(0)
        private val SIGHASH_ALL = fourBytesLittleEndian(1)

        private val SCRIPT_CODE_PREFIX = "1976a914".fromHexString()
        private val SCRIPT_CODE_SUFFIX = "88ac".fromHexString()

        private val SEGWIT_MARKER = oneByte(0)
        private val SEGWIT_FLAG = oneByte(1)

        private val SEGWIT_SCRIPT_SIG = oneByte(0)

        fun parseRawTxHex(rawTxHex: String) {
            val rawTx = ByteBufferReader.getInstance(rawTxHex.fromHexString())

            println("-----")
            val version = rawTx.readBytes(4)
            println("Version: ${version.toHexString()} (${version.toLittleEndianByteBuffer().getInt()})")

            val segwitMarker = rawTx.readByte()
            println("SegWit Marker: $segwitMarker")

            val segwitFlag = rawTx.readByte()
            println("SegWit Flag: $segwitFlag")

            println("")
            println("--== Inputs ==--")
            val inputCount = rawTx.readByte()
            println("Input count: $inputCount")

            for (i in 0 until inputCount) {
                val txId = rawTx.readBytes(32)
                println("TxId: ${txId.toHexString()}")

                val txIdIndex = rawTx.readBytes(4)
                println("Tx index: ${txIdIndex.toHexString()} (${txIdIndex.toLittleEndianByteBuffer().getInt()})")

                val scriptSigSize = rawTx.readByte()
                println("ScriptSig size: $scriptSigSize")

                val sequence = rawTx.readBytes(4)
                println("Sequence: ${sequence.toHexString()}")
            }

            println("")
            println("--== Outputs ==--")
            val outputCount = rawTx.readByte()
            println("Output count: $outputCount")

            for (i in 0 until outputCount) {
                val amount = rawTx.readBytes(8)
                println("Amount: ${amount.toHexString()} (${amount.toLittleEndianByteBuffer().getLong()})")

                val scriptPubKeySize = rawTx.readByte()
                println("scriptPubKey size: $scriptPubKeySize")

                val scriptPubKey = rawTx.readBytes(scriptPubKeySize.toInt())
                println("scriptPubKey: ${scriptPubKey.toHexString()}")
            }

            println("")
            println("--== Witness ==--")
            for (i in 0 until inputCount) {
                val itemsCount = rawTx.readByte()
                println("Witness items count: $itemsCount")

                for (j in 0 until itemsCount) {
                    val itemSize = rawTx.readByte()
                    println("Witness items size: $itemSize")

                    val item = rawTx.readBytes(itemSize.toInt())
                    println("Witness items: ${item.toHexString()}")
                }
            }

            println("")
            val locktime = rawTx.readBytes(4)
            println("Locktime: ${locktime.toHexString()}")
        }
    }

    data class Builder(
        var network: Network = Network.TESTNET,
        var txIn: MutableList<TxIn> = mutableListOf(),
        var txOut: MutableList<TxOut> = mutableListOf()
    ) {
        fun addTxIn(txIn: TxIn) = apply { this.txIn.add(txIn) }
        fun addTxOut(txOut: TxOut) = apply { this.txOut.add(txOut) }

        fun build() = Transaction(network, txIn, txOut)
    }

    fun sign(index: Int, prvKey: PrivateKey): ByteArray {
        val txIn = txInList[index]

        val hashPrevouts = doubleSha256(getOutpoints())
        val hashSequence = doubleSha256((1..txInList.size).fold(byteArrayOf()) { acc, _ -> acc + SEQUENCE })

        val outpoint = getOutpoint(index)

        val inputPubKeyHash = txIn.privateKey.getPublicKey().getKeyHash()
        val scriptCode = SCRIPT_CODE_PREFIX + inputPubKeyHash + SCRIPT_CODE_SUFFIX

        val hashOutputs = doubleSha256(getOutputs())

        val sequenceData = Utils.sequenceData(
            VERSION,
            hashPrevouts,
            hashSequence,
            outpoint,
            scriptCode,
            txIn.valueSerialized(),
            SEQUENCE,
            hashOutputs,
            LOCKTIME,
            SIGHASH_ALL
        )

        val digest = doubleSha256(sequenceData)

        return prvKey.signData(digest) + oneByte(1)
    }

    fun serialize(): ByteArray {
        val signatures = txInList.mapIndexed { listIdx, txIn -> sign(listIdx, txIn.privateKey) }

        val sequenceData = Utils.sequenceData(
            VERSION,
            SEGWIT_MARKER,
            SEGWIT_FLAG,

            oneByte(txInList.size.toByte()),        // Count of inputs

            (txInList.indices).foldIndexed(byteArrayOf()) { listIdx, acc, _ ->
                acc + ByteBuffer.allocate(36).put(getOutpoint(listIdx)).array() + SEGWIT_SCRIPT_SIG + SEQUENCE
            },

            oneByte(txOutList.size.toByte()),       // Count of outputs

            txOutList.fold(byteArrayOf()) { acc, element -> acc + element.toOutput() },

            // Witness
            txInList.foldIndexed(byteArrayOf()) { listIdx, acc, txIn ->
                acc +
                        oneByte(0x02) +
                        oneByte(signatures[listIdx].size.toByte()) +
                        signatures[listIdx] +
                        oneByte(0x21) +
                        txIn.privateKey.getPublicKey().getCompressedKeydata()
            },

            LOCKTIME
        )

        return sequenceData
    }

    private fun getOutpoints(): ByteArray = txInList.fold(byteArrayOf()) { acc, element ->
        acc + element.toOutpoint()
    }

    private fun getOutpoint(index: Int): ByteArray = txInList[index].toOutpoint()

    private fun getOutputs(): ByteArray = txOutList.fold(byteArrayOf()) { acc, element ->
        acc + element.toOutput()
    }

}

data class TxIn(val txId: String, val index: Int, val amount: Int, val privateKey: PrivateKey)

data class TxOut(val amount: Int, val pubHash: String)

// Outpoint = transaction ID in little endian + transaction ID index in little endian
fun TxIn.toOutpoint(): ByteArray = txId.fromHexString().reversedArray() + fourBytesLittleEndian(index)
fun TxIn.valueSerialized(): ByteArray = eightBytesLittleEndian(amount)

fun TxOut.getScriptPubKey(): ByteArray = oneByte(0x00) + oneByte(0x14) + decodeP2WPKHAddress(address = pubHash)
fun TxOut.toOutput(): ByteArray = eightBytesLittleEndian(amount) + oneByte(0x16) + getScriptPubKey()

internal class ByteBufferReader(
    private val buffer: ByteBuffer
) {
    companion object {
        fun getInstance(arr: ByteArray) = ByteBufferReader(ByteBuffer.wrap(arr))
    }

    fun readByte(): Byte {
        return buffer.get()
    }

    fun readBytes(n: Int): ByteArray {
        val readBuffer = ByteArray(n)
        buffer.get(readBuffer)
        return readBuffer
    }
}

fun ByteArray.toLittleEndianByteBuffer(): ByteBuffer {
    return ByteBuffer.wrap(this).order(LITTLE_ENDIAN)
}
