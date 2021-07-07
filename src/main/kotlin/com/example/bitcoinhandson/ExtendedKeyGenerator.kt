package com.example.bitcoinhandson

import io.ipfs.multibase.Base58
import org.springframework.stereotype.Component
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class Network(val versionPrivateKey: Int, val versionPublicKey: Int) {
    MAINNET(76066276, 76067358),
    TESTNET(70615956, 70617039);
}

@Component
class ExtendedKeyGenerator {
    companion object {
        const val DEFAULT_HMAC_KEY = "Bitcoin seed"
        const val HMAC_HASH_ALGO = "HmacSHA512"
        const val CHECKSUM_HASH_ALGO = "SHA-256"
    }

    fun masterPrivateKey(seed: ByteArray, network: Network): PrivateKey {
        val hmacSha512 = Mac.getInstance(HMAC_HASH_ALGO)
        val hmacKeySpec = SecretKeySpec(DEFAULT_HMAC_KEY.toByteArray(), HMAC_HASH_ALGO)

        hmacSha512.init(hmacKeySpec)
        val hash = hmacSha512.doFinal(seed)

        secretKey = hash.slice(0..31).toByteArray()
        chainCode = hash.slice(32..63).toByteArray()

        return privateKey(network, 0, 0, 0, chainCode, secretKey)
    }

    fun privateKey(
        network: Network,
        depth: Byte,
        parentFingerprint: Int,
        childNumber: Int,
        chainCode: ByteArray,
        keyData: ByteArray
    ): PrivateKey {
        val keySerialized = serializeKey(
            network.versionPrivateKey,
            depth,
            parentFingerprint,
            childNumber,
            chainCode,
            keyData
        )

        val sha256 = MessageDigest.getInstance(CHECKSUM_HASH_ALGO)
        val hashedKey = sha256.digest(keySerialized)
        val reHashedKey = sha256.digest(hashedKey)

        val checksum = reHashedKey.slice(0..3).toByteArray()

        return PrivateKey(keyData, chainCode, Base58.encode(keySerialized + checksum))
    }

    private fun serializeKey(
        version: Int,
        depth: Byte,
        parentFingerprint: Int,
        childNumber: Int,
        chainCode: ByteArray,
        keyData: ByteArray
    ): ByteArray {
        val sequence = listOf<ByteArray>(
            ByteBuffer.allocate(4).putInt(version).array(),
            ByteBuffer.allocate(1).put(depth).array(),
            ByteBuffer.allocate(4).putInt(parentFingerprint).array(),
            ByteBuffer.allocate(4).putInt(childNumber).array(),
            chainCode,
            ByteBuffer.allocate(1).array(),
            keyData
        )

        return sequence.fold(byteArrayOf()) { acc, item -> acc + item }
    }

    lateinit var secretKey: ByteArray
    lateinit var chainCode: ByteArray
}
