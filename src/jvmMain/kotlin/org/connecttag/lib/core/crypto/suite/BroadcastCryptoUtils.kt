package org.connecttag.lib.core.crypto.suite

@Deprecated(
    message = "Use org.connecttag.lib.core.crypto.broadcast.BroadcastCryptoUtils instead.",
)
public object BroadcastCryptoUtils {
    public fun generateNonce(): String = org.connecttag.lib.core.crypto.broadcast.BroadcastCryptoUtils.generateNonce()

    public fun hmacSign(payload: String, key: String): String {
        return org.connecttag.lib.core.crypto.broadcast.BroadcastCryptoUtils.hmacSign(payload, key)
    }

    public fun verifyHmac(payload: String, key: String, signatureBase64: String?): Boolean {
        return org.connecttag.lib.core.crypto.broadcast.BroadcastCryptoUtils.verifyHmac(payload, key, signatureBase64)
    }

    public fun aesGcmEncrypt(plain: String, secret: String): String {
        return org.connecttag.lib.core.crypto.broadcast.BroadcastCryptoUtils.aesGcmEncrypt(plain, secret)
    }

    public fun aesGcmDecrypt(base64: String, secret: String): String? {
        return org.connecttag.lib.core.crypto.broadcast.BroadcastCryptoUtils.aesGcmDecrypt(base64, secret)
    }
}
