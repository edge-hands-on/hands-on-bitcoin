package com.example.bitcoinhandson

import com.example.bitcoinhandson.Network.MAINNET
import com.example.bitcoinhandson.Network.TESTNET
import com.example.bitcoinhandson.Utils.Companion.generateKeyDataAndChainCode
import com.example.bitcoinhandson.Utils.Companion.getEcCurve
import com.example.bitcoinhandson.Utils.Companion.sha256ripemd160
import com.example.bitcoinhandson.Utils.Companion.sequenceData
import com.example.bitcoinhandson.Utils.Companion.serializeKey
import com.example.bitcoinhandson.Utils.Companion.sha256
import io.ipfs.multibase.Base58
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.nio.ByteBuffer
import java.security.Security

class PublicKey private constructor(
    val network: Network,
    val keyData: ECPoint,
    val encodedKey: String,
    val checksum: ByteArray,
    val depth: Byte,
    val parentFingerprint: ByteArray,
    val childNumber: Int
) {
    companion object {
        val P2PKH_PREFIXES: Map<Network, Byte> = mapOf(
            MAINNET to 0x00,
            TESTNET to 0x6F
        )

        val P2WPKH_PREFIXES: Map<Network, String> = mapOf(
            MAINNET to "bc",
            TESTNET to "tb"
        )

        fun getInstance(
            network: Network,
            keyData: ECPoint,
            chainCode: ByteArray,
            depth: Byte,
            parentFingerprint: ByteArray,
            childNumber: Int
        ): PublicKey {
            val (keySerialized, checksum) = serializeKey(
                network.publicKey,
                depth,
                parentFingerprint,
                childNumber,
                chainCode,
                keyData.getEncoded(true)
            )

            return PublicKey(network, keyData, keySerialized, checksum, depth, parentFingerprint, childNumber)
        }
    }

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun getFingerprint() = sha256ripemd160(keyData.getEncoded(true)).slice(0..3).toByteArray()

    fun derivedChild(parentChainCode: ByteArray, index: Int): PublicKey {
        val sequenceData = sequenceData(
            keyData.getEncoded(true),
            ByteBuffer.allocate(4).putInt(index).array()
        )

        val (childKeyData, childChainCode) = generateKeyDataAndChainCode(sequenceData, parentChainCode)

        val childPublicKey = FixedPointCombMultiplier()
            .multiply(getEcCurve().g, childKeyData)
            .add(keyData)

        return getInstance(
            network,
            childPublicKey,
            childChainCode,
            (depth + 1).toByte(),
            getFingerprint(),
            index
        )
    }

    fun getP2PKHAddress(): String {
        val prefix: Byte = P2PKH_PREFIXES[network]!!
        val payload = ByteBuffer.allocate(1).put(prefix).array() + sha256ripemd160(keyData.getEncoded(true))
        val payloadChecksum = sha256(sha256(payload)).slice(0..3).toByteArray()

        return Base58.encode(payload + payloadChecksum)
    }

    fun getP2WPKHAddress(): String {
        val prefix = P2WPKH_PREFIXES[network]!!
        val version = 0
        val keyHash = sha256ripemd160(keyData.getEncoded(true))

        return Bech32.encodeAddress(prefix, version, keyHash)
    }
}
