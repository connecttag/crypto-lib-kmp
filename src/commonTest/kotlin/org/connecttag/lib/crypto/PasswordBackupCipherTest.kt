package org.connecttag.lib.crypto

import kotlin.test.*
import kotlinx.coroutines.test.runTest

class PasswordBackupCipherTest {
    private val cipher=PasswordBackupCipher()
    // Independent PBKDF2-SHA256/AES-GCM vector using the legacy Java backup byte order.
    private val legacy="41534d41415f454e435f7631000102030405060708090a0b0c0d0e0f202122232425262728292a2bc21b5ac809c1b9bdab46c64eb9408a2824e5e5d1c5dbb535bda77cc205521e73c910e50ec359c772038d8667595e58bf0bd50ba1492a75313c0de6077b5e7a8aa862247e2623501ead52f15501a48104395b5251ead9974c8d7fb4b16eebbd"
    private val password="أسماء-نسخة-١٢٣"
    private val plain="[{\"name\":\"اختبار\",\"phones\":[{\"number\":\"+967771234567\",\"type\":\"Mobile\"}]}]"
    @Test fun readsLegacyArabicPassword()=runTest { assertEquals(plain,cipher.decrypt(legacy.hexToByteArray(),password).decodeToString()) }
    @Test fun exchangesEncryptedBackups()=runTest { val bytes=cipher.encrypt(plain.encodeToByteArray(),password);assertTrue(cipher.isEncrypted(bytes));assertEquals(plain,cipher.decrypt(bytes,password).decodeToString()) }
    @Test fun rejectsWrongPasswordAndCorruption()=runTest {
        val bytes=legacy.hexToByteArray()
        assertFailsWith<Exception> { cipher.decrypt(bytes,"wrong") }
        bytes[bytes.lastIndex]=(bytes.last().toInt() xor 1).toByte()
        assertFailsWith<Exception> { cipher.decrypt(bytes,password) }
        assertFailsWith<Exception> { cipher.decrypt(byteArrayOf(1,2,3),password) }
    }
}
