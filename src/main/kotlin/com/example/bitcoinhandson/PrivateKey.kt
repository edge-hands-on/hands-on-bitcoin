package com.example.bitcoinhandson

import com.example.bitcoinhandson.Utils.Companion.bigIntegerToByteArray
import com.example.bitcoinhandson.Utils.Companion.generateKeyDataAndChainCode
import com.example.bitcoinhandson.Utils.Companion.getEcCurve
import com.example.bitcoinhandson.Utils.Companion.sha256ripemd160
import com.example.bitcoinhandson.Utils.Companion.sequenceData
import com.example.bitcoinhandson.Utils.Companion.serializeKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.Security

class PrivateKey private constructor(
    val network: Network,
    val keyData: BigInteger,
    val chainCode: ByteArray,
    val encodedKey: String,
    val checksum: ByteArray,
    val depth: Byte,
    val parentFingerprint: ByteArray,
    val childNumber: Int
) {
    companion object {
        const val EC_ALGO = "secp256k1"
        const val START_HARDENED_INDEX = 0x80000000

        fun getInstance(
            network: Network,
            keyData: BigInteger,
            chainCode: ByteArray,
            depth: Byte,
            parentFingerprint: ByteArray,
            childNumber: Int
        ): PrivateKey {
            val (keySerialized, checksum) = serializeKey(
                network.privateKey,
                depth,
                parentFingerprint,
                childNumber,
                chainCode,
                bigIntegerToByteArray(keyData)
            )

            return PrivateKey(
                network,
                keyData,
                chainCode,
                keySerialized,
                checksum,
                depth,
                parentFingerprint,
                childNumber
            )
        }
    }

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun getFingerprint() = sha256ripemd160(getPublicKeyDate().getEncoded(true)).slice(0..3).toByteArray()

    fun getPublicKey(): PublicKey {
        val publicKeyData = getPublicKeyDate()

        return PublicKey.getInstance(network, publicKeyData, chainCode, depth, parentFingerprint, childNumber)
    }

    fun deriveChild(index: Int, hardened: Boolean = false): PrivateKey {
        val childIndex = index + if (hardened) START_HARDENED_INDEX else 0

        val sequenceData = sequenceData(
            if (hardened) {
                ByteBuffer.allocate(33)
                    .put(0)
                    .put(bigIntegerToByteArray(keyData))
                    .array()
            } else {
                getPublicKeyDate().getEncoded(true)
            },
            ByteBuffer.allocate(4).putInt(childIndex.toInt()).array()
        )

        val (childKeyData, childChainCode) = generateKeyDataAndChainCode(sequenceData, chainCode)

        val childPrivateKey = keyData
            .add(childKeyData)
            .mod(getEcCurve().n)

        return getInstance(
            network,
            childPrivateKey,
            childChainCode,
            (depth + 1).toByte(),
            getFingerprint(),
            childIndex.toInt()
        )
    }

    fun deriveChilds(indices: IntRange, hardened: Boolean = false): List<PrivateKey> {
        val childs = mutableListOf<PrivateKey>()

        for (index in indices.first..indices.last) {
            childs.add(deriveChild(index, hardened))
        }

        return childs
    }

    private fun getPublicKeyDate(): ECPoint {
        if (keyData.bitLength() > getEcCurve().n.bitLength()) {
            throw RuntimeException("Number must be less than N")
        }

        return FixedPointCombMultiplier().multiply(getEcCurve().g, keyData)
    }
}
