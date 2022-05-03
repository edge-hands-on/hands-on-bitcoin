package com.example.bitcoinhandson

import org.springframework.stereotype.Component
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Component
class SeedGenerator {
    companion object {
        private const val CRYPT_ALGO = "PBKDF2WithHmacSHA512"
        private const val ITERATIONS = 2048
        private const val KEY_LENGTH = 8 * 64 // 64 bytes
    }

    fun fromMnemonic(mnemonic: String, passphrase: String): SecretKey {
        val factory = SecretKeyFactory.getInstance(CRYPT_ALGO)
        val keySpecPbkfd2 = PBEKeySpec(
            mnemonic.toCharArray(),
            "mnemonic$passphrase".toByteArray(),
            ITERATIONS,
            KEY_LENGTH
        )

        return factory.generateSecret(keySpecPbkfd2)
    }
}
