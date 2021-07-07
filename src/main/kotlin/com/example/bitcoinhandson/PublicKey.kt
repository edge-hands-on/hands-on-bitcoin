package com.example.bitcoinhandson

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import java.security.MessageDigest
import java.security.Security

class PublicKey(
    val keyData: ECPoint
) {
    companion object {
        const val SHA_FINGERPRINT = "SHA-256"
        const val RIPE_FINGERPRINT = "RipeMD160"
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
}
