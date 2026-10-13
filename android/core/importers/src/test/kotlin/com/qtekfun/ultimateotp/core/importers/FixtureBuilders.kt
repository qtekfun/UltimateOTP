// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.importers

import com.qtekfun.ultimateotp.core.crypto.KdfParams
import com.qtekfun.ultimateotp.core.crypto.PasswordKdf
import com.qtekfun.ultimateotp.core.crypto.Pbkdf2
import com.qtekfun.ultimateotp.core.crypto.Scrypt
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The generator of the self-made fixtures: it writes, from the documented formats
 * (docs/import-formats.md), the files that the real exports in `resources/fixtures` do not cover
 * (steam, hotp, unsupported entry types, hostile parameters, tampering). Salts and nonces are
 * fixed, so the files are the same on every run. Encryption uses the JDK (AES-GCM) and the
 * scrypt/PBKDF2 of :core:crypto, which `ForeignKdfTest` pins to the RFC test vectors.
 */
object FixtureBuilders {
    const val PASSWORD = "correct horse"

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun gcm(
        key: ByteArray,
        nonce: ByteArray,
        plain: ByteArray,
        aad: ByteArray? = null,
    ): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad != null) c.updateAAD(aad)
        return c.doFinal(plain)
    }

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    private fun fill(
        n: Int,
        seed: Int,
    ) = ByteArray(n) { (it * 7 + seed).toByte() }

    /** An Aegis db with one entry of every supported type, plus a motp one that must be rejected. */
    val AEGIS_DB =
        """
        {"version":3,"entries":[
         {"type":"totp","uuid":"1","name":"alice@example.com","issuer":"Example","note":"work","favorite":true,
          "icon":null,"info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"period":60},"groups":["g1"]},
         {"type":"hotp","uuid":"2","name":"bob","issuer":"Bank","favorite":false,
          "info":{"secret":"GEZDGNBVGY3TQOJQ","algo":"SHA1","digits":6,"counter":41},"groups":[]},
         {"type":"steam","uuid":"3","name":"gabe","issuer":"Steam",
          "info":{"secret":"JRZCL47CMXVOQMNPZR2F7J4RGI","algo":"SHA1","digits":5,"period":30}},
         {"type":"motp","uuid":"4","name":"old","issuer":"X","info":{"secret":"GEZDGNBVGY3TQOJQ","algo":"MD5","digits":6,"period":10,"pin":"1234"}},
         {"type":"totp","uuid":"5","name":"broken","issuer":"Y","info":{"secret":"not base32 !!","algo":"SHA1","digits":6,"period":30}}
        ],"groups":[{"uuid":"g1","name":"Work"}]}
        """.trimIndent()

    /** An encrypted Aegis vault with a biometric slot first and a password slot (scrypt N=[n]). */
    fun aegisEncrypted(
        db: String = AEGIS_DB,
        password: String = PASSWORD,
        n: Int = 1024,
        r: Int = 8,
        p: Int = 1,
        passwordSlot: Boolean = true,
        tamper: Boolean = false,
    ): String {
        val master = fill(32, 1)
        val salt = fill(32, 2)
        val kek = Scrypt.derive(password.toByteArray(), salt, n, r, p, 32)
        val slotNonce = fill(12, 3)
        val wrapped = gcm(kek, slotNonce, master)
        val dbNonce = fill(12, 4)
        var sealed = gcm(master, dbNonce, db.toByteArray())
        if (tamper) sealed[0] = (sealed[0].toInt() xor 1).toByte()
        val dbCipher = sealed.copyOfRange(0, sealed.size - 16)
        val dbTag = sealed.copyOfRange(sealed.size - 16, sealed.size)
        val slot =
            """{"type":${if (passwordSlot) 1 else 2},"uuid":"s1","key":"${hex(wrapped.copyOfRange(0, 32))}",
              "key_params":{"nonce":"${hex(slotNonce)}","tag":"${hex(wrapped.copyOfRange(32, 48))}"},
              "n":$n,"r":$r,"p":$p,"salt":"${hex(salt)}"}"""
        return """{"version":1,"header":{"slots":[$slot],"params":{"nonce":"${hex(
            dbNonce,
        )}","tag":"${hex(dbTag)}"}},"db":"${b64(dbCipher)}"}"""
    }

    val TWO_FAS_SERVICES =
        """
        [{"name":"Example","secret":"jbsw y3dp ehpk 3pxp","otp":{"account":"alice@example.com","digits":6,"period":30,
           "algorithm":"SHA1","tokenType":"TOTP"},"groupId":"g1"},
         {"name":"Bank","secret":"GEZDGNBVGY3TQOJQ","otp":{"account":"bob","digits":8,"algorithm":"SHA256","tokenType":"HOTP","counter":5}},
         {"name":"Odd","secret":"GEZDGNBVGY3TQOJQ","otp":{"account":"x","tokenType":"WEIRD"}}]
        """.trimIndent()

    fun twoFasEncrypted(
        password: String = PASSWORD,
        services: String = TWO_FAS_SERVICES,
        schema: Int = 4,
    ): String {
        val salt = fill(256, 5)
        val iv = fill(12, 6)
        val key = Pbkdf2.derive(Pbkdf2.HMAC_SHA256, password.toByteArray(), salt, 10_000, 32)
        val data = gcm(key, iv, services.toByteArray())
        return """{"services":[],"groups":[{"id":"g1","name":"Personal"}],"schemaVersion":$schema,
            "servicesEncrypted":"${b64(data)}:${b64(salt)}:${b64(iv)}"}"""
    }

    fun twoFasPlain(
        schema: Int = 4,
        services: String = TWO_FAS_SERVICES,
    ) = """{"services":$services,"groups":[{"id":"g1","name":"Personal"}],"schemaVersion":$schema}"""

    val ANDOTP_JSON =
        """
        [{"secret":"JBSWY3DPEHPK3PXP","issuer":"Example","label":"alice@example.com","digits":6,"type":"TOTP","algorithm":"SHA1",
          "period":30,"tags":["Work"]},
         {"secret":"GEZDGNBVGY3TQOJQ","label":"Bank - bob","digits":8,"type":"HOTP","algorithm":"SHA256","counter":9,"tags":[]},
         {"secret":"JRZCL47CMXVOQMNPZR2F7J4RGI","label":"Steam - gabe","digits":5,"type":"STEAM","algorithm":"SHA1","period":30},
         {"secret":"GEZDGNBVGY3TQOJQ","label":"mobile","digits":6,"type":"MOTP","algorithm":"MD5","period":10}]
        """.trimIndent()

    fun andOtpNew(
        password: String = PASSWORD,
        iterations: Int = 2000,
        json: String = ANDOTP_JSON,
    ): ByteArray {
        val salt = fill(12, 7)
        val nonce = fill(12, 8)
        val key = Pbkdf2.derive(Pbkdf2.HMAC_SHA1, password.toByteArray(), salt, iterations, 32)
        return ByteBuffer.allocate(4).putInt(iterations).array() + salt + nonce + gcm(key, nonce, json.toByteArray())
    }

    fun andOtpOld(
        password: String = PASSWORD,
        json: String = ANDOTP_JSON,
    ): ByteArray {
        val nonce = fill(12, 9)
        val key = MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
        return nonce + gcm(key, nonce, json.toByteArray())
    }

    val RAIVO_JSON =
        """
        [{"kind":"TOTP","issuer":"Example","account":"alice@example.com","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1",
          "digits":"6","timer":"30","counter":"0","iconType":"raivo_repository","iconValue":"x"},
         {"kind":"HOTP","issuer":"Bank","account":"bob","secret":"GEZDGNBVGY3TQOJQ","algorithm":"SHA256","digits":"8","timer":"30","counter":"12"},
         {"kind":"MOTP","issuer":"Odd","account":"x","secret":"GEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":"6","timer":"30","counter":"0"}]
        """.trimIndent()

    fun zip(
        name: String,
        content: String,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            z.putNextEntry(ZipEntry(name))
            z.write(content.toByteArray())
            z.closeEntry()
        }
        return out.toByteArray()
    }

    val PROTON_JSON =
        """
        {"version":1,"entries":[
         {"id":"1","content":{"uri":"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30",
           "entry_type":"Totp","name":"alice@example.com"},"note":"hello"},
         {"id":"2","content":{"uri":"steam://JRZCL47CMXVOQMNPZR2F7J4RGI","entry_type":"Steam","name":"gabe"},"note":null},
         {"id":"3","content":{"uri":"https://example.com","entry_type":"Totp","name":"junk"},"note":null}]}
        """.trimIndent()

    fun protonEncrypted(
        password: String = PASSWORD,
        json: String = PROTON_JSON,
    ): String {
        val salt = fill(16, 10)
        val nonce = fill(12, 11)
        val key = PasswordKdf.deriveRaw(password.toByteArray(), KdfParams(2, 19L * 1024 * 1024, salt))
        val sealed = gcm(key, nonce, json.toByteArray(), "proton.authenticator.export.v1".toByteArray())
        return """{"version":1,"salt":"${b64(salt)}","content":"${b64(nonce + sealed)}"}"""
    }
}
