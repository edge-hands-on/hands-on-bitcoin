package com.example.bitcoinhandson

import com.example.bitcoinhandson.Utils.Companion.generateKeyDataAndChainCode
import com.example.bitcoinhandson.Utils.Companion.getEcCurve
import com.example.bitcoinhandson.Utils.Companion.sequenceData
import com.example.bitcoinhandson.Utils.Companion.serializeKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.nio.ByteBuffer
import java.security.MessageDigest
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
        const val SHA_FINGERPRINT = "SHA-256"
        const val RIPE_FINGERPRINT = "RipeMD160"

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

    fun getShaFingerprint(): ByteArray {
        val hashSha256 = MessageDigest.getInstance(SHA_FINGERPRINT)
        return hashSha256.digest(keyData.getEncoded(true))
    }

    fun getShortFingerprint(): ByteArray {
        val ripeDigest = MessageDigest.getInstance(RIPE_FINGERPRINT)
        val publicKeySha256Ripe = ripeDigest.digest(getShaFingerprint())
        return publicKeySha256Ripe.slice(0..3).toByteArray()
    }

    fun derivedChild(parentChainCode: ByteArray, index: Int): PublicKey {
        val sequenceData = sequenceData(
            keyData.getEncoded(true),
            ByteBuffer.allocate(4).putInt(index).array()
        )

        val (childKeyData, childChainCode) = generateKeyDataAndChainCode(sequenceData, parentChainCode)

        val childPublicKey = FixedPointCombMultiplier()
            .multiply(getEcCurve().g, childKeyData)
            .add(keyData)

        return getInstance(network, childPublicKey, childChainCode, (depth + 1).toByte(), getShortFingerprint(), index)
    }
}
