package me.phh.ims

import java.security.MessageDigest
import kotlin.random.Random

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun ByteArray.toMD5(): String = MessageDigest.getInstance("MD5").digest(this).toHex()

fun String.toMD5(): String = toByteArray().toMD5()

fun randomBytes(count: Int): ByteArray = Random.Default.nextBytes(count)
