@file:OptIn(ExperimentalUnsignedTypes::class)
package org.connecttag.lib.core.crypto.hashing

import kotlin.math.abs
import kotlin.math.sin

/** Synchronous compatibility digests; authenticated encryption uses WebCrypto separately. */
public actual object DigestUtils {
    public actual val MD5 = "MD5"
    public actual val SHA1 = "SHA-1"
    public actual val SHA256 = "SHA-256"
    public actual fun digest(bytes: ByteArray): String = sha256(bytes)
    public actual fun digest(bytes: ByteArray, algorithm: String): String = when (algorithm.uppercase().replace("-", "")) {
        "MD5" -> md5(bytes)
        "SHA1" -> sha1(bytes)
        "SHA256" -> sha256(bytes)
        else -> throw IllegalArgumentException(algorithm)
    }
    private fun Int.rol(n: Int) = (this shl n) or (this ushr (32 - n))
    private fun Int.ror(n: Int) = (this ushr n) or (this shl (32 - n))
    private fun padded(bytes: ByteArray, little: Boolean): ByteArray {
        val output = bytes.copyOf(((bytes.size + 9 + 63) / 64) * 64)
        output[bytes.size] = 0x80.toByte()
        val bits = bytes.size.toLong() * 8
        repeat(8) { i -> output[output.size - 8 + i] = (bits ushr (if (little) i * 8 else (7 - i) * 8)).toByte() }
        return output
    }
    private fun words(bytes: ByteArray, offset: Int, little: Boolean): IntArray = IntArray(16) { i ->
        var value = 0
        repeat(4) { j -> value = value or ((bytes[offset + i * 4 + j].toInt() and 255) shl (if (little) j * 8 else (3 - j) * 8)) }
        value
    }
    private fun hex(words: IntArray, little: Boolean): String = buildString {
        for (word in words) repeat(4) { i ->
            val b = (word ushr (if (little) i * 8 else (3 - i) * 8)) and 255
            append("0123456789abcdef"[b ushr 4]); append("0123456789abcdef"[b and 15])
        }
    }
    public actual fun md5(bytes: ByteArray): String {
        val input = padded(bytes, true)
        val h = intArrayOf(0x67452301, 0xefcdab89.toInt(), 0x98badcfe.toInt(), 0x10325476)
        val shifts = intArrayOf(7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21)
        val constants = IntArray(64) { (abs(sin((it + 1).toDouble())) * 4294967296.0).toLong().toInt() }
        for (offset in input.indices step 64) {
            val w = words(input, offset, true)
            var a=h[0]; var b=h[1]; var c=h[2]; var d=h[3]
            repeat(64) { i ->
                val f: Int; val g: Int
                when (i / 16) {
                    0 -> { f=(b and c) or (b.inv() and d); g=i }
                    1 -> { f=(d and b) or (d.inv() and c); g=(5*i+1)%16 }
                    2 -> { f=b xor c xor d; g=(3*i+5)%16 }
                    else -> { f=c xor (b or d.inv()); g=(7*i)%16 }
                }
                val next=b+(a+f+constants[i]+w[g]).rol(shifts[(i/16)*4+i%4])
                a=d; d=c; c=b; b=next
            }
            h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d
        }
        return hex(h,true)
    }
    public actual fun sha1(bytes: ByteArray): String {
        val input=padded(bytes,false)
        val h=intArrayOf(0x67452301,0xefcdab89.toInt(),0x98badcfe.toInt(),0x10325476,0xc3d2e1f0.toInt())
        for(offset in input.indices step 64) {
            val w=words(input,offset,false).copyOf(80)
            for(i in 16..79) w[i]=(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]).rol(1)
            var a=h[0];var b=h[1];var c=h[2];var d=h[3];var e=h[4]
            repeat(80) { i ->
                val f=when(i/20){0->(b and c) or (b.inv() and d);2->(b and c) or (b and d) or (c and d);else->b xor c xor d}
                val k=when(i/20){0->0x5a827999;1->0x6ed9eba1;2->0x8f1bbcdc.toInt();else->0xca62c1d6.toInt()}
                val t=a.rol(5)+f+e+k+w[i];e=d;d=c;c=b.rol(30);b=a;a=t
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e
        }
        return hex(h,false)
    }
    public actual fun sha256(bytes: ByteArray): String {
        val input=padded(bytes,false)
        val h=intArrayOf(0x6a09e667,0xbb67ae85.toInt(),0x3c6ef372,0xa54ff53a.toInt(),0x510e527f,0x9b05688c.toInt(),0x1f83d9ab,0x5be0cd19)
        val k=uintArrayOf(0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u)
        for(offset in input.indices step 64) {
            val w=words(input,offset,false).copyOf(64)
            for(i in 16..63) {
                val x=w[i-15];val y=w[i-2]
                w[i]=w[i-16]+(x.ror(7) xor x.ror(18) xor (x ushr 3))+w[i-7]+(y.ror(17) xor y.ror(19) xor (y ushr 10))
            }
            var a=h[0];var b=h[1];var c=h[2];var d=h[3];var e=h[4];var f=h[5];var g=h[6];var z=h[7]
            repeat(64) { i ->
                val t1=z+(e.ror(6) xor e.ror(11) xor e.ror(25))+((e and f) xor (e.inv() and g))+k[i].toInt()+w[i]
                val t2=(a.ror(2) xor a.ror(13) xor a.ror(22))+((a and b) xor (a and c) xor (b and c))
                z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z
        }
        return hex(h,false)
    }
}
