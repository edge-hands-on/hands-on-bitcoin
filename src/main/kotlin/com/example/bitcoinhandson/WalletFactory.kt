package com.example.bitcoinhandson

import org.springframework.stereotype.Component

@Component
class WalletFactory(
    private val seedGenerator: SeedGenerator,
    private val extendedKeyGenerator: ExtendedKeyGenerator,
    private val jsonRPC: JsonRPC
) {
    fun getWallet(network: Network, mnemonic: String, passphrase: String): Wallet {
        log.debug("Input mnemonic: $mnemonic")
        log.debug("Key password: $passphrase")

        val seed = seedGenerator.fromMnemonic(mnemonic, passphrase)

        val masterXPrvKey = extendedKeyGenerator.masterPrivateKey(seed.encoded, Network.TESTNET)
        val masterXPubKey = masterXPrvKey.getPublicKey()

        log.debug("Master private key: ${masterXPrvKey.encodedKey}")
        log.debug("Master public key: ${masterXPubKey.encodedKey}")

        val purpose = masterXPrvKey.deriveChild(44, true)
        val coinType = purpose.deriveChild(1, true)
        val account = coinType.deriveChild(0, true)

        log.debug("Account private key: ${account.encodedKey}")
        log.debug("Account public key: ${account.getPublicKey().encodedKey}")

        val receiving = account.deriveChild(0, false)
        val change = account.deriveChild(1, false)

        log.debug("Receiving private key: ${receiving.encodedKey}")
        log.debug("Receiving public key: ${receiving.getPublicKey().encodedKey}")

        return Wallet(network, jsonRPC, masterXPrvKey, purpose, coinType, account, receiving, change)
    }
}
