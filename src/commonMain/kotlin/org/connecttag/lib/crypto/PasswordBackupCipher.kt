package org.connecttag.lib.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.PBKDF2
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.random.CryptographyRandom
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.DelicateCryptographyApi

/** Binary-compatible password backups. No platform file or UI types cross this boundary. */
@OptIn(DelicateCryptographyApi::class)
class PasswordBackupCipher {
    private val magic = "ASMAA_ENC_v1".encodeToByteArray()
    fun isEncrypted(bytes: ByteArray): Boolean = bytes.size >= magic.size + 44 &&
        magic.indices.all { magic[it] == bytes[it] }

    private suspend fun key(password: String, salt: ByteArray): AES.GCM.Key {
        val provider = CryptographyProvider.Default
        val secret = provider.get(PBKDF2).secretDerivation(
            digest = SHA256, iterations = 65_536, outputSize = 256.bits, salt = salt
        ).deriveSecretToByteArray(password.encodeToByteArray())
        return provider.get(AES.GCM).keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, secret)
    }

    suspend fun encrypt(bytes: ByteArray, password: String): ByteArray {
        val salt = CryptographyRandom.nextBytes(16)
        val iv = CryptographyRandom.nextBytes(12)
        val ciphertext = key(password, salt).cipher().encryptWithIv(iv, bytes)
        return magic + salt + iv + ciphertext
    }

    suspend fun decrypt(bytes: ByteArray, password: String): ByteArray {
        require(isEncrypted(bytes))
        val offset = magic.size
        val salt = bytes.copyOfRange(offset, offset + 16)
        val iv = bytes.copyOfRange(offset + 16, offset + 28)
        return key(password, salt).cipher().decryptWithIv(iv, bytes.copyOfRange(offset + 28, bytes.size))
    }
}
