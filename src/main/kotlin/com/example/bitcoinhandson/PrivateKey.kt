package com.example.bitcoinhandson

import com.example.bitcoinhandson.Utils.Companion.serializeKey
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.math.BigInteger

class PrivateKey(
    val network: Network,
    val keyData: ByteArray,
    val chainCode: ByteArray,
    val encodedKey: String,
    val checksum: ByteArray,
    val depth: Byte,
    val parentFingerprint: Int,
    val childNumber: Int
) {
    companion object {
        const val EC_ALGO = "secp256k1"
    }

    fun getPublicKey(): PublicKey {
        val curveParams = CustomNamedCurves.getByName(EC_ALGO)
        val curve = ECDomainParameters(
            curveParams.curve,
            curveParams.g,
            curveParams.n,
            curveParams.h
        )

        val privateKey = BigInteger(keyData.toHexString(), 16)
        if (privateKey.bitLength() > curve.n.bitLength()) {
            throw RuntimeException("Number must be less than N")
        }

        val publicKey = FixedPointCombMultiplier().multiply(curve.g, privateKey)

        val (keySerialized, checksum) = serializeKey(
            network.publicKey,
            depth,
            parentFingerprint,
            childNumber,
            chainCode,
            publicKey.getEncoded(true)
        )

        return PublicKey(network, publicKey, keySerialized, checksum)
    }
}
