package com.example.bitcoinhandson

import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import java.math.BigInteger

class PrivateKey(
    val keyData: ByteArray,
    val chainCode: ByteArray,
    val encodedKey: String
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

        return PublicKey(publicKey)
    }
}
