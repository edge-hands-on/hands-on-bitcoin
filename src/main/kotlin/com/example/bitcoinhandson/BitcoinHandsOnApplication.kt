package com.example.bitcoinhandson

import org.springframework.boot.CommandLineRunner
import org.springframework.boot.WebApplicationType
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ComponentScan
import java.math.BigInteger
import java.security.spec.KeySpec
import java.util.Arrays
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec


@EnableAutoConfiguration
@ComponentScan
class BitcoinHandsOnApplication() : CommandLineRunner {
    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val passphrase = ""
    private val expectedSeedOutputHex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    private val expectedPrivateKey = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"


    override fun run(vararg args: String) {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        val keyspec: KeySpec = PBEKeySpec(mnemonic.toCharArray(), "mnemonic$passphrase".toByteArray(), 2048, 8 * 64)
        val seed = factory.generateSecret(keyspec)

        println(Arrays.toString(seed.encoded))
        println(seed.encoded.toHexString())

        println(expectedSeedOutputHex == seed.encoded.toHexString())

//        var hash = Hash.sha512hmac(hexa, Buffer.from('Bitcoin seed'));

//        return new HDPrivateKey({
//            network: Network.get(network) || Network.defaultNetwork,
//            depth: 0,
//            parentFingerPrint: 0,
//            childIndex: 0,
//            privateKey: hash.slice(0, 32),
//            chainCode: hash.slice(32, 64)
//        });
    }
}

fun ByteArray.toHexString() : String {
    return this.joinToString("") { "%02x".format(it) }
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
