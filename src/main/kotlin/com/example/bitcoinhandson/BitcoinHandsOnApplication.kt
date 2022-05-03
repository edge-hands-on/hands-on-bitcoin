package com.example.bitcoinhandson

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
    private val walletFactory: WalletFactory
) : CommandLineRunner {
    private val mnemonic1 = "anchor rural seven own option north midnight calm emerge film steak shadow"
    private val passphrase1 = ""

    private val mnemonic2 = "wish auto scale naive spend below fan double lizard audit indoor toddler"
    private val passphrase2 = ""

    override fun run(vararg args: String) {
        Security.addProvider(BouncyCastleProvider())

        val wallet1 = walletFactory.getWallet(mnemonic1, passphrase1)
        val wallet2 = walletFactory.getWallet(mnemonic2, passphrase2)

        println("Printings addresses")
        println("\nWallet1:")
        wallet1.addresses.forEachIndexed { index, address -> println("$index $address") }

        println("\nWallet2:")
        wallet2.addresses.forEachIndexed { index, address -> println("$index $address") }

        wallet1.sendTransaction(1, "tb1q50aukgvsafckcaqlquqkwmv9jawkx3l0xp32ej", 100000)
    }
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
