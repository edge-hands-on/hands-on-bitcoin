package com.example.bitcoinhandson

import com.example.bitcoinhandson.Utils.Companion.serializeKey
import org.springframework.stereotype.Component
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class Network(val privateKey: Int, val publicKey: Int) {
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
        val (keySerialized, checksum) = serializeKey(
            network.privateKey,
            depth,
            parentFingerprint,
            childNumber,
            chainCode,
            keyData
        )

        return PrivateKey(network, keyData, chainCode, keySerialized, checksum, depth, parentFingerprint, childNumber)
    }

    lateinit var secretKey: ByteArray
    lateinit var chainCode: ByteArray
}
