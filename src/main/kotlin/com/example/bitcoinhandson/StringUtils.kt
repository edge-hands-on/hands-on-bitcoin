package com.example.bitcoinhandson

fun ByteArray.toHexString() : String {
    return this.joinToString("") { "%02x".format(it) }
}

fun String.fromHexString(): ByteArray {
    require(length % 2 == 0) { "Must have an even length" }

    return ByteArray(length / 2) {
        Integer.parseInt(this, it * 2, (it + 1) * 2, 16).toByte()
    }
}
