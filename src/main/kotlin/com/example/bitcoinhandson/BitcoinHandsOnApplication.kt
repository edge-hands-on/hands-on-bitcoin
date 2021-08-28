package com.example.bitcoinhandson

import com.example.bitcoinhandson.Network.MAINNET
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
    private val mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    //    private val mnemonic = "wish auto scale naive spend below fan double lizard audit indoor toddler"
//    private val mnemonic = "off arrive awkward together twenty anxiety save jaguar assume trigger sadness purse"
    private val passphrase = ""

    override fun run(vararg args: String) {
        Security.addProvider(BouncyCastleProvider())

        println("Input mnemonic: $mnemonic")
        println("Key password: $passphrase")

        val seed = seedGenerator.fromMnemonic(mnemonic, passphrase)

        val masterXPrvKey = extendedKeyGenerator.masterPrivateKey(seed.encoded, MAINNET)
        val masterXPubKey = masterXPrvKey.getPublicKey()

        println(masterXPrvKey.encodedKey)
        println(masterXPubKey.getShortFingerprint().toHexString())
        println(masterXPubKey.encodedKey)
    }

    /*
    mnemonic = "off arrive awkward together twenty anxiety save jaguar assume trigger sadness purse"

    m/44h/0h/0h/0/0: 17tG2pVbTaEtBtpCdGxnraEyCDMJHZPzUm
    m/44h/0h/0h/0/1: 1Exn9Eh6Y5U3LKuWSkDFg9UNpEV69Jce7N
    m/44h/0h/0h/0/2: 1Ao8hPnSEjLBk5gyZN1WxVKuUsrPit5pq
    m/44h/0h/0h/0/3: 1MXoBqzYTA53vg11RsTENcdgUwngMNbb9E
    m/44h/0h/0h/0/4: 15YVo61jP3myVrNmUZ4xyF2vGTD8a9q6AY
    m/44h/0h/0h/0/5: 1QAEK4yPKXZd98zFnnj6UsRT3XprtXNuGE
    m/44h/0h/0h/0/6: 1CQUS7kQLZdJdPWY5JvNabKZn1WGLkUifJ
    m/44h/0h/0h/0/7: 14b19N7ntnzscBdnHSe3qmSUJNoY6xU8eX
    m/44h/0h/0h/0/8: 19NZBibDAk9Zov1fWYVKZ1E76eM72sB5f1
    m/44h/0h/0h/0/9: 1GAYg9tzxs1nspHtNBdV8Ww4RJf4DpGVBx
    m/44h/0h/0h/0/10: 1968eZkvNLexaDL31NfhpWvASSybsWYbNn
    m/44h/0h/0h/0/11: 16JHJg55GDZsCAzN7qctBtD1S7ykRBry9C
    m/44h/0h/0h/0/12: 1Loi7TK5h9UCWoiKwknLWZyWyQ6F42aCaK
    m/44h/0h/0h/0/13: 1BT3j4GBEteNm2Afodwr9ZSzQtgh8pb6Lc
    m/44h/0h/0h/0/14: 17xjUEZD4rhmi1fvQbkTLxPwsVy91sZ3Vk
    m/44h/0h/0h/0/15: 1Hocgc6mro3Bp1HaFbqnyP6A5Qx7iRs9m3
    m/44h/0h/0h/0/16: 1HFniYoSauVih9baecRAWT6etM8jbph111
    m/44h/0h/0h/0/17: 1DWWPWjHXfEN4jdQBVXAwuQeArsa4UYt5u
    m/44h/0h/0h/0/18: 147U6gxcFA5gBhj7JHNZgPQ3LygssQ3HCL
    m/44h/0h/0h/0/19: 14rxiT7xUWfaMPKzv2XdPHSJ7uKFhat4sZ
     */
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
