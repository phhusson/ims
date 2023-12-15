//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import java.security.MessageDigest
import kotlin.random.Random

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun ByteArray.toMD5(): String = MessageDigest.getInstance("MD5").digest(this).toHex()

fun String.toMD5(): String = toByteArray().toMD5()

fun String.hexToByteArray(): ByteArray {
    // from https://stackoverflow.com/a/66614516
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

fun randomBytes(count: Int): ByteArray = Random.Default.nextBytes(count)
