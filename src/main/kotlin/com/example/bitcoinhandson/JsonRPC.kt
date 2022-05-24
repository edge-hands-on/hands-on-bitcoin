package com.example.bitcoinhandson

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.stereotype.Component
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.Base64
import java.util.UUID

@Component
class JsonRPC(
    private val objectMapper: ObjectMapper = jacksonObjectMapper()
) {
    companion object {
        const val USERNAME = "bitcoinrpc"
        const val PASSWORD = "Jfq0Mq2qpb2J4xGqe/p52IO/a5Vwut2lvVGsKBYSLjuw"

        const val HOST_IP = "3.71.22.222"
    }

    fun <T> request(method: String, params: Array<Any>, valueType: Class<T>): T? {
        return makeRequest(method, params)?.let { objectMapper.treeToValue(it, valueType) }
    }

    fun <T> requestToList(method: String, params: Array<Any>, valueType: Class<T>): List<T>? {
        return makeRequest(method, params)?.let {
            val resultList = mutableListOf<T>()
            for (item in it) {
                resultList.add(objectMapper.treeToValue(item, valueType))
            }
            resultList
        }
    }

    private fun makeRequest(method: String, params: Array<Any>): JsonNode? {
        val json = JsonBody(method, params)
        val serializedJSON = objectMapper.writeValueAsString(json)
        log.debug("-- Request JsonRPC: $serializedJSON")

        val client = HttpClient.newBuilder().build();
        val request = HttpRequest.newBuilder()
            .header("Authorization", basicAuth(USERNAME, PASSWORD))
            .uri(URI.create("http://$HOST_IP:8332"))
            .POST(HttpRequest.BodyPublishers.ofString(serializedJSON))
            .build();

        val response = client.send(request, HttpResponse.BodyHandlers.ofString());

        val jsonResult = objectMapper.readValue(response.body(), JsonRpcResult::class.java)
        log.debug("JsonResult: $jsonResult")

        if (jsonResult.error != null) {
            log.error("Error: ${jsonResult.error}")
            return null
        }

        return jsonResult.result
    }

    private fun basicAuth(username: String, password: String): String? {
        return "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())
    }

    data class JsonBody(
        val method: String,
        val params: Array<Any>,
        val jsonrpc: String = "1.0",
        val id: String = UUID.randomUUID().toString()
    )

    data class JsonRpcResult(
        val result: JsonNode,
        val error: JsonError?,
        val id: String
    )

    data class JsonError(
        val code: Int,
        val message: String
    )
}
