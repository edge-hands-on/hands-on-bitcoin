package com.example.bitcoinhandson

import com.example.bitcoinhandson.Network.TESTNET
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.WebApplicationType
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ComponentScan
import java.security.Security

@EnableAutoConfiguration
@ComponentScan
class BitcoinHandsOnApplication(
    private val seedGenerator: SeedGenerator,
    private val extendedKeyGenerator: ExtendedKeyGenerator
) : CommandLineRunner {
    //private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val mnemonic = "wish auto scale naive spend below fan double lizard audit indoor toddler"
    private val passphrase = ""

    override fun run(vararg args: String) {
        Security.addProvider(BouncyCastleProvider())

        println("Input mnemonic: $mnemonic")
        println("Key password: $passphrase")

        val seed = seedGenerator.fromMnemonic(mnemonic, passphrase)

        val masterXPrvKey = extendedKeyGenerator.masterPrivateKey(seed.encoded, TESTNET)
        val masterXPubKey = masterXPrvKey.getPublicKey()

        println(masterXPrvKey.encodedKey)
        println(masterXPubKey.getShortFingerprint().toHexString())
        println(masterXPubKey.encodedKey)
    }
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
