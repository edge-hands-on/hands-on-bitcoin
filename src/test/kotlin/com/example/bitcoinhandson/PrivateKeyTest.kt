package com.example.bitcoinhandson

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PrivateKeyTest {

    @Test
    fun `should generate correct child private key`() {
        val expectedEncodedKey =
            "xprv9ukW2UsmeQP9NB14w61cimzwEKbUJxHCypMb1PpEafjCETz69a6tp8aYdMkHfz6U49Ut262f9MpGZkCna1zDhEfW2BGkSehvrxd5ueR4TBe"
        val expectedShortFingerprint = "5525def6"
        val expectedChecksum = "ef8f9529"

        val seedHex = "5eb00bbddcf069084889a8ab91555681" +
                "65f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c4" +
                "3daea6690f20ad3d8d48b2d2ce9e38e4"

        val xPrivateKey = ExtendedKeyGenerator().masterPrivateKey(seedHex.fromHexString(), Network.MAINNET)

        val xChildPrivateKey = xPrivateKey.deriveChild(0)

        assertThat(xChildPrivateKey.network).isEqualTo(Network.MAINNET)
        assertThat(xChildPrivateKey.encodedKey).isEqualTo(expectedEncodedKey)
        assertThat(xChildPrivateKey.getFingerprint().toHexString()).isEqualTo(expectedShortFingerprint)
        assertThat(xChildPrivateKey.checksum.toHexString()).isEqualTo(expectedChecksum)
    }

    @Test
    fun `should generate correct hardened child private key`() {
        val expectedEncodedKey =
            "xprv9ukW2Usuz4v7Yd2EC4vNXaMckdsEdgBA9n7MQbqMJbW9FuHDWWjDwzEM2h6XmFnrzX7JVmfcNWMEVoRauU6hQpbokqPPNTbdycW9fHSPYyF"
        val expectedShortFingerprint = "2e5aec06"
        val expectedChecksum = "25ef709a"

        val seedHex = "5eb00bbddcf069084889a8ab91555681" +
                "65f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c4" +
                "3daea6690f20ad3d8d48b2d2ce9e38e4"

        val xPrivateKey = ExtendedKeyGenerator().masterPrivateKey(seedHex.fromHexString(), Network.MAINNET)

        val xChildPrivateKey = xPrivateKey.deriveChild(0, true)

        assertThat(xChildPrivateKey.network).isEqualTo(Network.MAINNET)
        assertThat(xChildPrivateKey.encodedKey).isEqualTo(expectedEncodedKey)
        assertThat(xChildPrivateKey.getFingerprint().toHexString()).isEqualTo(expectedShortFingerprint)
        assertThat(xChildPrivateKey.checksum.toHexString()).isEqualTo(expectedChecksum)
    }
}
