package org.connecttag.lib.core.crypto.hashing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD5
import platform.CoreCrypto.CC_MD5_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA1
import platform.CoreCrypto.CC_SHA1_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH

@OptIn(ExperimentalForeignApi::class)
public actual object DigestUtils {
    public actual val MD5: String = "MD5"
    public actual val SHA1: String = "SHA-1"
    public actual val SHA256: String = "SHA-256"

    public actual fun digest(bytes: ByteArray): String = sha256(bytes)

    public actual fun digest(bytes: ByteArray, algorithm: String): String = when (algorithm.uppercase()) {
        "MD5" -> md5(bytes)
        "SHA-1", "SHA1" -> sha1(bytes)
        else -> sha256(bytes)
    }

    public actual fun md5(bytes: ByteArray): String {
        val digest = UByteArray(CC_MD5_DIGEST_LENGTH)
        val ubytes = bytes.asUByteArray()
        digest.usePinned { pinnedDigest ->
            if (ubytes.isEmpty()) {
                CC_MD5(null, 0u, pinnedDigest.addressOf(0))
            } else {
                ubytes.usePinned { pinnedBytes ->
                    CC_MD5(pinnedBytes.addressOf(0), ubytes.size.toUInt(), pinnedDigest.addressOf(0))
                }
            }
        }
        return digest.toHexString()
    }

    public actual fun sha1(bytes: ByteArray): String {
        val digest = UByteArray(CC_SHA1_DIGEST_LENGTH)
        val ubytes = bytes.asUByteArray()
        digest.usePinned { pinnedDigest ->
            if (ubytes.isEmpty()) {
                CC_SHA1(null, 0u, pinnedDigest.addressOf(0))
            } else {
                ubytes.usePinned { pinnedBytes ->
                    CC_SHA1(pinnedBytes.addressOf(0), ubytes.size.toUInt(), pinnedDigest.addressOf(0))
                }
            }
        }
        return digest.toHexString()
    }

    public actual fun sha256(bytes: ByteArray): String {
        val digest = UByteArray(CC_SHA256_DIGEST_LENGTH)
        val ubytes = bytes.asUByteArray()
        digest.usePinned { pinnedDigest ->
            if (ubytes.isEmpty()) {
                CC_SHA256(null, 0u, pinnedDigest.addressOf(0))
            } else {
                ubytes.usePinned { pinnedBytes ->
                    CC_SHA256(pinnedBytes.addressOf(0), ubytes.size.toUInt(), pinnedDigest.addressOf(0))
                }
            }
        }
        return digest.toHexString()
    }

    private fun UByteArray.toHexString(): String =
        joinToString(separator = "") { byte ->
            byte.toString(radix = 16).padStart(2, '0')
        }
}
