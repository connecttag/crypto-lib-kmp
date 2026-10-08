package org.connecttag.lib.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class CryptoCommonTest {
    @Test
    fun testBase64EncodingDecoding() {
        val original = "Hello ConnectTag Crypto!"
        val encoded = Base64Utils.encode(original)
        val decoded = Base64Utils.decode(encoded)
        assertEquals(original, decoded)

        val bytes = byteArrayOf(1, 2, 3, 4, 5, -128, 127)
        val encodedBytes = Base64Utils.encode(bytes)
        val decodedBytes = Base64Utils.decodeToBytes(encodedBytes)
        assertContentEquals(bytes, decodedBytes)
    }

    @Test
    fun testHashAndDigest() {
        val hash = HashUtils.sha256("test-input")
        assertEquals(64, hash.length)

        val sha1 = HashUtils.sha1("test-input")
        assertEquals(40, sha1.length)
    }
}
