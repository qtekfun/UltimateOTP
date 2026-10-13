// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.core.vault.secure

/** Small secrets (the vault key, the device private keys) encrypted at rest. */
interface SecretStore {
    /** True if reading needs a recent biometric or device-credential authentication. */
    val requiresUserAuthentication: Boolean

    fun put(
        name: String,
        secret: ByteArray,
    )

    /**
     * @return the secret, or null if none was stored.
     * @throws AuthenticationRequiredException if the user must authenticate first (app lock).
     * @throws KeyInvalidatedException if the Keystore key is gone (restore from sync or export).
     */
    fun get(name: String): ByteArray?

    fun delete(name: String)

    fun contains(name: String): Boolean

    /**
     * Cheap proof that [put] would work right now, without storing anything.
     * @throws AuthenticationRequiredException if the user must authenticate first.
     * @throws KeyInvalidatedException if the Keystore key is unusable.
     */
    fun checkUsable()
}

class AuthenticationRequiredException(
    cause: Throwable? = null,
) : Exception("user authentication required", cause)

class KeyInvalidatedException(
    cause: Throwable? = null,
) : Exception("keystore key invalidated", cause)

/** For tests and previews: keeps secrets in memory, can simulate the app lock. */
class InMemorySecretStore(
    override val requiresUserAuthentication: Boolean = false,
) : SecretStore {
    private val secrets = mutableMapOf<String, ByteArray>()

    /** When false, reads and writes fail like a Keystore key whose authentication window expired. */
    var authenticated = true

    /** When true, every use fails like a Keystore key that was invalidated. */
    var invalidated = false

    override fun put(
        name: String,
        secret: ByteArray,
    ) {
        checkUsable()
        secrets[name] = secret.copyOf()
    }

    override fun get(name: String): ByteArray? {
        if (invalidated) throw KeyInvalidatedException()
        if (requiresUserAuthentication && !authenticated && name in secrets) throw AuthenticationRequiredException()
        return secrets[name]?.copyOf()
    }

    override fun delete(name: String) {
        secrets.remove(name)
    }

    override fun contains(name: String): Boolean = name in secrets

    override fun checkUsable() {
        if (invalidated) throw KeyInvalidatedException()
        if (requiresUserAuthentication && !authenticated) throw AuthenticationRequiredException()
    }
}
