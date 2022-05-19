package com.example.bitcoinhandson

class Wallet(
    private val network: Network,
    private val jsonRPC: JsonRPC,
    val masterXPrvKey: PrivateKey,
    private val purpose: PrivateKey,
    private val coinType: PrivateKey,
    private val account: PrivateKey,
    private val receiving: PrivateKey,
    private val change: PrivateKey
) {
    companion object {
        const val BATCH_ADDRS = 3
    }

    val receiveAddrs: List<PrivateKey> by lazy { generateAddresses(receiving) }
    val changeAddrs: List<PrivateKey> by lazy { generateAddresses(change) }

    fun getRawTransaction(txId: String, blockId: String): GetRawTransactionResponse? =
        jsonRPC.request("getrawtransaction", arrayOf(txId, true, blockId), GetRawTransactionResponse::class.java)

    fun testmempoolaccept(signedTxHex: String): List<TestMempoolAcceptResponse>? =
        jsonRPC.requestToList("testmempoolaccept", arrayOf(arrayOf(signedTxHex)), TestMempoolAcceptResponse::class.java)

    fun sendrawtransaction(signedTxHex: String): String? =
        jsonRPC.request("sendrawtransaction", arrayOf(signedTxHex), String::class.java)

    fun printAddresses() {
        println("-- Receiving addresses:")
        receiveAddrs.forEachIndexed { index, address ->
            println(
                "$index ${
                    address.getPublicKey().getP2WPKHAddress()
                }"
            )
        }
        println("")
        println("-- Change addresses:")
        changeAddrs.forEachIndexed { index, address ->
            println(
                "$index ${
                    address.getPublicKey().getP2WPKHAddress()
                }"
            )
        }
    }

    private fun generateAddresses(privateKey: PrivateKey): List<PrivateKey> {
        val addresses = mutableListOf<PrivateKey>()

        val childs = privateKey.deriveChildren(0 until BATCH_ADDRS, false)
        for (index in childs.indices) {
            log.debug("Index [$index] private key: ${childs[index].encodedKey}")
            log.debug("Index [$index] public key: ${childs[index].getPublicKey().encodedKey}")
            log.debug("P2PKH Address [$index]: ${childs[index].getPublicKey().getP2PKHAddress()}")
            log.debug("P2WPKH Address [$index]: ${childs[index].getPublicKey().getP2WPKHAddress()}")

            addresses.add(childs[index])
        }

        return addresses
    }
}
