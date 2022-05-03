package com.example.bitcoinhandson

import org.bouncycastle.util.encoders.Hex
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Wallet(
    private val jsonRPC: JsonRPC,
    private val masterXPrvKey: PrivateKey,
    private val purpose: PrivateKey,
    private val coinType: PrivateKey,
    private val account: PrivateKey,
    private val receiving: PrivateKey
) {
    val addresses: List<String> by lazy { generateAddresses(20) }

    fun getTransaction() {
        jsonRPC.request(
            "getrawtransaction", arrayOf(
                "36ad7e49cd6c8a05c5d431ce07c4e7658b392e2209fadadaffdb87974516e73c",
                true,
                "000000007d61d56ce7eec3707c2233946a0d7d6d5b0cb41cec398b10e96e5467"
            )
        )
    }

    fun sendTransaction(fromIndex: Int, to: String, value: Int) {
        val version = 1 // (0x00 0x00 0x00 0x01) (0x01000000)
        println(Hex.toHexString(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(version).array()))
    }

    private fun generateAddresses(count: Int): List<String> {
        val addresses = mutableListOf<String>()

        val childs = receiving.deriveChilds(0 until count, false)
        for (index in childs.indices) {
            log.debug("Index [$index] private key: ${childs[index].encodedKey}")
            log.debug("Index [$index] public key: ${childs[index].getPublicKey().encodedKey}")
            log.debug("P2PKH Address [$index]: ${childs[index].getPublicKey().getP2PKHAddress()}")
            log.debug("P2WPKH Address [$index]: ${childs[index].getPublicKey().getP2WPKHAddress()}")

            addresses.add(childs[index].getPublicKey().getP2WPKHAddress())
        }

        return addresses
    }
}
