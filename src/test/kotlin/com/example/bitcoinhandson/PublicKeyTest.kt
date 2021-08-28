package com.example.bitcoinhandson

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PublicKeyTest {

    @Test
    fun `should generate correct public key`() {
        val expectedEncodedKey = "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"
        val expectedShaFingerprint = "b690735f6fa658805d17567d9bf43f6f9eb73efb52d4b3a87492aa05c08db511"
        val expectedShortFingerprint = "73c5da0a"
        val expectedChecksum = "c7fe61f5"

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

    @Test
    fun `should generate correct child public key`() {
        val expectedEncodedKey = "xpub68jrRzQfUmwSaf5Y37Yd5uwfnMRxiR14M3HBonDr91GB7GKEh7R9Mvu2UeCtbASfXZ9FdNo9FwFx6a37HNXUDiXVQFXuadXmevRBa3y7rL8"
        val expectedShaFingerprint = "8fd5e30c2fabae3306c2afc06bdfb44d50c7d110ebfcf3e4436311457ce3246c"
        val expectedShortFingerprint = "5525def6"
        val expectedChecksum = "910cd129"

        val seedHex = "5eb00bbddcf069084889a8ab91555681" +
                "65f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c4" +
                "3daea6690f20ad3d8d48b2d2ce9e38e4"

        val xPrivateKey = ExtendedKeyGenerator().masterPrivateKey(seedHex.fromHexString(), Network.MAINNET)

        val xPublicKey = xPrivateKey.getPublicKey()
        val xChildPublicKey = xPublicKey.derivedChild(xPrivateKey.chainCode, 0)

        assertThat(xChildPublicKey.network).isEqualTo(Network.MAINNET)
        assertThat(xChildPublicKey.encodedKey).isEqualTo(expectedEncodedKey)
        assertThat(xChildPublicKey.getShaFingerprint().toHexString()).isEqualTo(expectedShaFingerprint)
        assertThat(xChildPublicKey.getShortFingerprint().toHexString()).isEqualTo(expectedShortFingerprint)
        assertThat(xChildPublicKey.checksum.toHexString()).isEqualTo(expectedChecksum)
    }
}
