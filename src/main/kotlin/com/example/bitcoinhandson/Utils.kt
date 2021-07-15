package com.example.bitcoinhandson

import com.example.bitcoinhandson.Network.MAINNET
import com.example.bitcoinhandson.Network.TESTNET
import io.ipfs.multibase.Base58
import java.nio.ByteBuffer
import java.security.MessageDigest

class Utils {
    companion object {
        fun serializeKey(
            network_key: Int,
            depth: Byte,
            parentFingerprint: Int,
            childNumber: Int,
            chainCode: ByteArray,
            keyData: ByteArray
        ): Pair<String, ByteArray> {
            val sequence = mutableListOf<ByteArray>(
                ByteBuffer.allocate(4).putInt(network_key).array(),
                ByteBuffer.allocate(1).put(depth).array(),
                ByteBuffer.allocate(4).putInt(parentFingerprint).array(),
                ByteBuffer.allocate(4).putInt(childNumber).array(),
                chainCode,
                if (network_key in arrayOf(MAINNET.privateKey, TESTNET.privateKey))
                    ByteBuffer.allocate(1).array()
                else
                    byteArrayOf(),
                keyData
            )

            val sequenceData = sequence.fold(byteArrayOf()) { acc, item -> acc + item }

            val sha256 = MessageDigest.getInstance(ExtendedKeyGenerator.CHECKSUM_HASH_ALGO)
            val hashedKey = sha256.digest(sequenceData)
            val reHashedKey = sha256.digest(hashedKey)

            val checksum = reHashedKey.slice(0..3).toByteArray()
            val serializedData = Base58.encode(sequenceData + checksum)

            return serializedData to checksum
        }
    }
}
