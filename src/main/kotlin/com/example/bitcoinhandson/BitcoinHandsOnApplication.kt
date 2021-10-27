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
//    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    //        private val mnemonic = "wish auto scale naive spend below fan double lizard audit indoor toddler"
    private val mnemonic = "layer edge fiction grain margin thing safe avocado left happy hip legal"
    private val passphrase = ""

    override fun run(vararg args: String) {
        Security.addProvider(BouncyCastleProvider())

        println("Input mnemonic: $mnemonic")
        println("Key password: $passphrase")

        val seed = seedGenerator.fromMnemonic(mnemonic, passphrase)

        val masterXPrvKey = extendedKeyGenerator.masterPrivateKey(seed.encoded, TESTNET)
        val masterXPubKey = masterXPrvKey.getPublicKey()

        println("\nMaster private key: ${masterXPrvKey.encodedKey}")
        println("Master public key: ${masterXPubKey.encodedKey}")

        val purpose = masterXPrvKey.deriveChild(44, true)
        val coinType = purpose.deriveChild(1, true)
        val account = coinType.deriveChild(0, true)
        println("\nAccount private key: ${account.encodedKey}")
        println("Account public key: ${account.getPublicKey().encodedKey}")

        val receiving = account.deriveChild(0, false)
        println("\nReceiving private key: ${receiving.encodedKey}")
        println("Receiving public key: ${receiving.getPublicKey().encodedKey}")

        val childs = receiving.deriveChilds(0..19, false)
        for (index in childs.indices) {
            println("\nIndex [$index] private key: ${childs[index].encodedKey}")
            println("Index [$index] public key: ${childs[index].getPublicKey().encodedKey}")
            println("P2PKH Address [$index]: ${childs[index].getPublicKey().getP2PKHAddress()}")
            println("P2WPKH Address [$index]: ${childs[index].getPublicKey().getP2WPKHAddress()}")
        }
    }

    /*
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    m/44'/1'/0'/0/0	  mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV
    m/44'/1'/0'/0/1	  mzpbWabUQm1w8ijuJnAof5eiSTep27deVH
    m/44'/1'/0'/0/2	  mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp
    m/44'/1'/0'/0/3	  mpW3iVi2Td1vqDK8Nfie29ddZXf9spmZkX
    m/44'/1'/0'/0/4	  n2BMo5arHDyAK2CM8c56eoEd18uEkKnRLC
    m/44'/1'/0'/0/5	  mvWgTTtQqZohUPnykucneWNXzM5PLj83an
    m/44'/1'/0'/0/6	  muTU2Av1EwnsyhieQhyPL7hgEf883LR4xg
    m/44'/1'/0'/0/7	  mwduZ8Ksa563v7rWdSPmqyKR4y2FeB5g8p
    m/44'/1'/0'/0/8	  miyBE85ro5zt9RseSzYVEbB3TfzkxgSm8C
    m/44'/1'/0'/0/9	  mnYwW7mU3jajB11vrpDZwZDrXwVfE5Jc31
    m/44'/1'/0'/0/10  mx3YNRT8Vg8QwFq5Z5MAVDDVHp4ihHsffn
    m/44'/1'/0'/0/11  myHL2QuECVYkx9Y94gyC6RSweLNnteETsB
    m/44'/1'/0'/0/12  mqevqtsdeR7WuqwiXnyFU72ULK627W2mFH
    m/44'/1'/0'/0/13  mmKyDn8NJwXvqFqWDNR9QnMfd8mwrHvynF
    m/44'/1'/0'/0/14  mnDmjqLKEBBMnzWtrz5LptNChiQNxYLK84
    m/44'/1'/0'/0/15  n1MsayUmxjiUyrbQs6F2megEA8azR1nYc1
    m/44'/1'/0'/0/16  mhhTTZMmNTjT4zzS5xVpXSDan9iHy31Z2b
    m/44'/1'/0'/0/17  mp8ML8bKSiheUJPompTj5GZEWJUPmr1eiH
    m/44'/1'/0'/0/18  mjtvWKf25G3heJkzVkBRYNmZmPypdEY3hj
    m/44'/1'/0'/0/19  n3Zb38sLaM21q8dwDNZq7AsJda9omg6PuP
     */
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
