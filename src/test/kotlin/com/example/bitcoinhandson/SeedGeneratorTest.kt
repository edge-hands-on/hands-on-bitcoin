package com.example.bitcoinhandson

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SeedGeneratorTest {

    @Test
    fun `should generate same seed for same mnemonic`() {
        val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val expectedSeedHex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

        val seed = SeedGenerator().fromMnemonic(mnemonic, "")

        assertThat(expectedSeedHex).isEqualTo(seed.encoded.toHexString())
    }
}
