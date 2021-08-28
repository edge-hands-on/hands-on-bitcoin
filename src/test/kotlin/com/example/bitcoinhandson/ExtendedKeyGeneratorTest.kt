package com.example.bitcoinhandson

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class ExtendedKeyGeneratorTest {

    @Test
    fun `should generate extended private key with expected chainCode, keyData and encoded key`() {
        val expectedMasterSecretKey = "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
        val expectedMasterChainCode = "7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e"
        val expectedEncodedPrivateKey =
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        val expectedPrivateKeyChecksum = "c94305d2"

        val seedHex = "5eb00bbddcf069084889a8ab91555681" +
                "65f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c4" +
                "3daea6690f20ad3d8d48b2d2ce9e38e4"

        val xPrivateKey = ExtendedKeyGenerator().masterPrivateKey(seedHex.fromHexString(), Network.MAINNET)

        assertThat(xPrivateKey.network).isEqualTo(Network.MAINNET)
        assertThat(xPrivateKey.keyData.toByteArray().toHexString()).isEqualTo(expectedMasterSecretKey)
        assertThat(xPrivateKey.chainCode.toHexString()).isEqualTo(expectedMasterChainCode)
        assertThat(xPrivateKey.encodedKey).isEqualTo(expectedEncodedPrivateKey)
        assertThat(xPrivateKey.checksum.toHexString()).isEqualTo(expectedPrivateKeyChecksum)
        assertThat(xPrivateKey.depth).isEqualTo(0)
        assertThat(xPrivateKey.parentFingerprint).isEqualTo(ByteBuffer.allocate(4).array())
        assertThat(xPrivateKey.childNumber).isEqualTo(0)
    }
}
