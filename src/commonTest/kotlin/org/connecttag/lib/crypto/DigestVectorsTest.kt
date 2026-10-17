package org.connecttag.lib.crypto
import org.connecttag.lib.core.crypto.hashing.DigestUtils
import kotlin.test.*
class DigestVectorsTest {
    @Test fun standardVectorsAcrossPlatforms() {
        assertEquals("d41d8cd98f00b204e9800998ecf8427e",DigestUtils.md5(byteArrayOf()))
        assertEquals("900150983cd24fb0d6963f7d28e17f72",DigestUtils.md5("abc".encodeToByteArray()))
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d",DigestUtils.sha1("abc".encodeToByteArray()))
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",DigestUtils.sha256("abc".encodeToByteArray()))
    }
}
