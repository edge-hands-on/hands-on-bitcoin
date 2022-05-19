package com.example.bitcoinhandson

import com.fasterxml.jackson.annotation.JsonProperty

data class GetRawTransactionResponse(
    @JsonProperty("in_active_chain")
    val inActiveChain: Boolean,
    val hex: String,
    val txid: String,
    val hash: String,
    val size: Int,
    val vsize: Int,
    val weight: Int,
    val version: Int,
    val locktime: Int,
    val vin: List<TransactionInput>,
    val vout: List<TransactionOutput>,
    val blockhash: String,
    val confirmations : Int,
    val time: Int,
    val blocktime: Int
)

data class TransactionInput(
    val txid: String,
    val vout: Int,
    val scriptSig: ScriptSig,
    val sequence: Long,
    val txinwitness: List<String>
)

data class ScriptSig(
    val asm: String,
    val hex: String
)

data class TransactionOutput(
    val value: Double,
    val n: Int,
    val scriptPubKey: ScriptPubKey
)

data class ScriptPubKey(
    val asm: String,
    val desc: String,
    val hex: String,
    val reqSigs: Int,
    val type: String,
    val address: String
)

data class TestMempoolAcceptResponse(
    val txid: String,
    val wtxid: String?,
    val allowed: Boolean,
    val vsize: Int?,
    val fees: Fees?,
    @JsonProperty("reject-reason")
    val rejectReason: String?
)

data class Fees(
    val base: Int
)
