//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import org.junit.Test

class UtilsTests {
    @Test
    fun toHex() {
        require("test".toByteArray().toHex() == "74657374")
    }

    @Test
    fun toMD5() {
        require("test".toMD5() == "098f6bcd4621d373cade4e832627b4f6")
    }

    @Test
    fun ranodmBytes() {
        require(randomBytes(8).toHex().length == 16)
    }
}
