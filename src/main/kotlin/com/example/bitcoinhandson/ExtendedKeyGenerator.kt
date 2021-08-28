package com.example.bitcoinhandson

import com.example.bitcoinhandson.Utils.Companion.generateKeyDataAndChainCode
import org.springframework.stereotype.Component
import java.nio.ByteBuffer

enum class Network(val privateKey: Int, val publicKey: Int) {
    MAINNET(76066276, 76067358),
    TESTNET(70615956, 70617039);
}

@Component
class ExtendedKeyGenerator {
    companion object {
        const val DEFAULT_HMAC_KEY = "Bitcoin seed"
        const val CHECKSUM_HASH_ALGO = "SHA-256"
    }

    fun masterPrivateKey(seed: ByteArray, network: Network): PrivateKey {
        val (secretKey, chainCode) = generateKeyDataAndChainCode(seed, DEFAULT_HMAC_KEY.toByteArray())

        return PrivateKey.getInstance(
            network,
            secretKey,
            chainCode,
            0,
            ByteBuffer.allocate(4).array(),
            0
        )
    }
}
