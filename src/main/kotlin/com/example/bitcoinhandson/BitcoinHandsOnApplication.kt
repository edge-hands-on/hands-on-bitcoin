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
    private val walletFactory: WalletFactory
) : CommandLineRunner {
    private val mnemonic1 = "anchor rural seven own option north midnight calm emerge film steak shadow"
    private val passphrase1 = ""

    private val mnemonic2 = "wish auto scale naive spend below fan double lizard audit indoor toddler"
    private val passphrase2 = ""

    override fun run(vararg args: String) {
        Security.addProvider(BouncyCastleProvider())

        val wallet1 = walletFactory.getWallet(TESTNET, mnemonic1, passphrase1)
        val wallet2 = walletFactory.getWallet(TESTNET, mnemonic2, passphrase2)

        println("Printings addresses")
        println("")

        println("--== Wallet1 ==--")
        wallet1.printAddresses()
        println("")

        println("--== Wallet2 ==--")
        wallet2.printAddresses()
        println("")

        println("Getting transaction description for 7d52825be5de437846e29d24319dae45c49da04bf43f83fa6847fab1c6bbf6ae")
        // Transaction with our code
        val result = wallet1.getRawTransaction(
            "7d52825be5de437846e29d24319dae45c49da04bf43f83fa6847fab1c6bbf6ae",
            "000000000000000ab7143223439025848691f853ac2f4328317f48f76eb88024"
        )
        println("Result: $result")
        println("")

        println("Parsing transaction:")
        result?.let { Transaction.parseRawTxHex(it.hex) }

        println("")
        println("Creating new transaction")
        // Creating new transaction
        result?.let{
            val inputAmount = (result.vout[0].value * 100000000).toInt()
            val outputAmount = inputAmount - 10000

            val transaction = Transaction.Builder()
                .addTxIn(
                    TxIn(
                        result.txid,
                        0,
                        (result.vout[0].value * 100000000).toInt(),
                        wallet1.receiveAddrs[0]
                    )
                )
                .addTxOut(TxOut(outputAmount, "tb1qchcxcmlsfkujhnzj2qz2a6epk542eqnu8xpn9j"))
                .build()

            val rawHexTx = transaction.serialize().toHexString()

            println("Testing if transaction can be sent")
            val testMempoolAcceptResponse = wallet1.testmempoolaccept(rawHexTx)
            println("Result: $testMempoolAcceptResponse")
            println("")

            println("Sending transaction")
            val sendRawTransactionResponse = wallet1.sendrawtransaction(rawHexTx)
            println("Result: $sendRawTransactionResponse")
            println("")
        }
    }
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
