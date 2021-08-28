package com.example.bitcoinhandson

import com.example.bitcoinhandson.Network.MAINNET
import com.example.bitcoinhandson.Network.TESTNET
import io.ipfs.multibase.Base58
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class Utils {
    companion object {
        const val HMAC_HASH_ALGO = "HmacSHA512"

        fun serializeKey(
            network_key: Int,
            depth: Byte,
            parentFingerprint: ByteArray,
            childNumber: Int,
            chainCode: ByteArray,
            keyData: ByteArray
        ): Pair<String, ByteArray> {
            val sequenceData = sequenceData(
                ByteBuffer.allocate(4).putInt(network_key).array(),
                ByteBuffer.allocate(1).put(depth).array(),
                parentFingerprint,
                ByteBuffer.allocate(4).putInt(childNumber).array(),
                chainCode,
                if (network_key in arrayOf(MAINNET.privateKey, TESTNET.privateKey))
                    ByteBuffer.allocate(1).array()
                else
                    byteArrayOf(),
                keyData
            )

            val sha256 = MessageDigest.getInstance(ExtendedKeyGenerator.CHECKSUM_HASH_ALGO)
            val hashedKey = sha256.digest(sequenceData)
            val reHashedKey = sha256.digest(hashedKey)

            val checksum = reHashedKey.slice(0..3).toByteArray()
            val serializedData = Base58.encode(sequenceData + checksum)

            return serializedData to checksum
        }

        fun generateKeyDataAndChainCode(inputData: ByteArray, hmacKey: ByteArray): Pair<BigInteger, ByteArray> {
            val hmacSha512 = Mac.getInstance(HMAC_HASH_ALGO)
            val hmacKeySpec = SecretKeySpec(hmacKey, HMAC_HASH_ALGO)

            hmacSha512.init(hmacKeySpec)
            val hash = hmacSha512.doFinal(inputData)

            val keyData = hash.slice(0..31).toByteArray()
            val chainCode = hash.slice(32..63).toByteArray()

            return Pair(BigInteger(1, keyData), chainCode)
        }

        fun sequenceData(vararg datas: ByteArray) = datas.fold(byteArrayOf()) { acc, item -> acc + item }

        fun getEcCurve(): ECDomainParameters {
            val curveParams = CustomNamedCurves.getByName(PrivateKey.EC_ALGO)
            return ECDomainParameters(
                curveParams.curve,
                curveParams.g,
                curveParams.n,
                curveParams.h
            )
        }

        fun bigIntegerToByteArray(bigInteger: BigInteger): ByteArray {
            val bigIntegerArray = bigInteger.toByteArray()
            if (bigIntegerArray[0] == 0.toByte())
                return bigIntegerArray.slice(1 until bigIntegerArray.size).toByteArray()

            return bigIntegerArray
        }
    }
}
