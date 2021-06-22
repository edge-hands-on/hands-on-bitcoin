package com.example.bitcoinhandson

import io.ipfs.multibase.Base58
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.WebApplicationType
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ComponentScan
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Security
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


@EnableAutoConfiguration
@ComponentScan
class BitcoinHandsOnApplication() : CommandLineRunner {
    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val passphrase = ""
    private val expectedSeedOutputHex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    private val expectedPrivateKey = "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
    private val expectedChainCode = "7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e"
    private val expectedCheckSum = "c94305d2"

    private val expectedXPrivateKey = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"

    private val expectedPublicKeyFingerprint = "73c5da0a"

    private val hmacKey = "Bitcoin seed"

    // Network livenet keys
    // xprivkey:76066276
    // xpubkey:76067358


    override fun run(vararg args: String) {
        Security.addProvider(BouncyCastleProvider())

        println("Input mnemonic: $mnemonic")
        println("Key password: $passphrase")

        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        val keySpecPbkfd2 = PBEKeySpec(
            mnemonic.toCharArray(),
            "mnemonic$passphrase".toByteArray(),
            2048,
            8 * 64) // 64  bytes
        val seed = factory.generateSecret(keySpecPbkfd2)

        println(Arrays.toString(seed.encoded))
        println(seed.encoded.toHexString())

        println(expectedSeedOutputHex == seed.encoded.toHexString())

        val keyBytes = hmacKey.toByteArray()
        val sha512Hmac = Mac.getInstance("HmacSHA512")
        val keySpecHmac = SecretKeySpec(keyBytes, "HmacSHA512")

        sha512Hmac.init(keySpecHmac)
        val hash = sha512Hmac.doFinal(seed.encoded)

        val privateKey = hash.slice(0..31).toByteArray()
        val chainCode = hash.slice(32..63).toByteArray()

        println(privateKey.toHexString())
        println(privateKey.toHexString() == expectedXPrivateKey)

        println(chainCode.toHexString())
        println(chainCode.toHexString() == expectedChainCode)

        //        var sequence = [
        //            arg.version, arg.depth, arg.parentFingerPrint, arg.childIndex, arg.chainCode,
        //            BufferUtil.emptyBuffer(1), arg.privateKey
        //        ];
        val sequence = listOf<ByteArray>(
            ByteBuffer.allocate(4).putInt(76066276).array(),
            BigInteger.valueOf(0).toByteArray(),
            ByteBuffer.allocate(4).array(),
            ByteBuffer.allocate(4).array(),
            chainCode,
            ByteBuffer.allocate(1).array(),
            privateKey
        )

        val concat = sequence.fold(byteArrayOf()) { acc, item -> acc + item }

        val sha256 = MessageDigest.getInstance("SHA-256")
        val hash1 = sha256.digest(concat)
        val hash2 = sha256.digest(hash1)

        val checksum = hash2.slice(0..3).toByteArray()
        println(checksum.toHexString())
        println(expectedCheckSum == checksum.toHexString())

        val xPrivKey = Base58.encode(concat + checksum)
        println(xPrivKey)
        println(expectedXPrivateKey == xPrivKey)

        val CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1")
        val CURVE = ECDomainParameters(
            CURVE_PARAMS.curve,
            CURVE_PARAMS.g,
            CURVE_PARAMS.n,
            CURVE_PARAMS.h
        )

        val bnPrivateKey = BigInteger(privateKey.toHexString(), 16)
        if (bnPrivateKey.bitLength() > CURVE.getN().bitLength()) {
            println("Number must be less than N")
            return
        }

        val publicKey = FixedPointCombMultiplier().multiply(CURVE.g, bnPrivateKey)
        val publicKeyCompressed = publicKey.getEncoded(true)

        val ripeDigest = MessageDigest.getInstance("RipeMD160")

        val publicKeySha256 = sha256.digest(publicKeyCompressed)
        val publicKeySha256Ripe = ripeDigest.digest(publicKeySha256)

        val publicKeyFingerprint = publicKeySha256Ripe.slice(0..3).toByteArray()

        println(publicKeyFingerprint.toHexString())
        println(publicKeyFingerprint.toHexString() == expectedPublicKeyFingerprint)

        // var privateKey = new PrivateKey(BN.fromBuffer(arg.privateKey), network);
        //  var publicKey = privateKey.toPublicKey();
        //  var size = HDPrivateKey.ParentFingerPrintSize = 4;
        //  var fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).slice(0, size);


//        return new HDPrivateKey({
//            network: Network.get(network) || Network.defaultNetwork,
//            depth: 0,
//            parentFingerPrint: 0,
//            childIndex: 0,
//            privateKey: hash.slice(0, 32),
//            chainCode: hash.slice(32, 64)
//        });

// HDPrivateKey.prototype._buildFromObject = function(arg) {
//  /* jshint maxcomplexity: 12 */
//  // TODO: Type validation
//  var buffers = {
//    version: 76066276,
//    depth: 0,
//    parentFingerPrint: 0,
//    childIndex: 0,
//    chainCode: 7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e,
//    privateKey: 1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67,
//    checksum: ''
//  };
//  return this._buildFromBuffers(buffers);
//};
    }
}

fun ByteArray.toHexString() : String {
    return this.joinToString("") { "%02x".format(it) }
}

fun main() {
    runApplication<BitcoinHandsOnApplication> {
        this.webApplicationType = WebApplicationType.NONE
    }
}
