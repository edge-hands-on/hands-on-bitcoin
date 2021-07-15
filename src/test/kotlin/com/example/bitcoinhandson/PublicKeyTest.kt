package com.example.bitcoinhandson

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PublicKeyTest {

    @Test
    fun `should generate correct public key`() {
        val expectedEncodedKey = "5FQT7TT6bZmQ6QjZkc6VPdD4mNSt3a7wWzw31SsYUFvvm7TPCAeGiyJZL1RZckautS4mP9nVWVf4YsFWtJeTy7LfHyZbqPu65CBzsdkQ5tsRt32fA"
        val expectedShaFingerprint = "b690735f6fa658805d17567d9bf43f6f9eb73efb52d4b3a87492aa05c08db511"
        val expectedShortFingerprint = "73c5da0a"
        val expectedChecksum = "01b46149"

        val seedHex = "5eb00bbddcf069084889a8ab91555681" +
                "65f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c4" +
                "3daea6690f20ad3d8d48b2d2ce9e38e4"

        val xPrivateKey = ExtendedKeyGenerator().masterPrivateKey(seedHex.fromHexString(), Network.MAINNET)
        val xPublicKey = xPrivateKey.getPublicKey()

        assertThat(xPublicKey.network).isEqualTo(Network.MAINNET)
        assertThat(xPublicKey.encodedKey).isEqualTo(expectedEncodedKey)
        assertThat(xPublicKey.getShaFingerprint().toHexString()).isEqualTo(expectedShaFingerprint)
        assertThat(xPublicKey.getShortFingerprint().toHexString()).isEqualTo(expectedShortFingerprint)
        assertThat(xPublicKey.checksum.toHexString()).isEqualTo(expectedChecksum)
    }
}
