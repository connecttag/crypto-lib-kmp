package org.connecttag.lib.core.crypto.hashing

public actual object HashUtils {
    public actual fun sha256(input: String): String =
        DigestUtils.sha256(input.encodeToByteArray())

    public actual fun hashPassword(password: String): String =
        sha256(password)

    public actual fun sha1(input: String): String =
        DigestUtils.sha1(input.encodeToByteArray())
}
