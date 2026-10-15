// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui

import android.app.Application
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem
import com.qtekfun.ultimateotp.ui.sync.accountProblemText
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Every problem the sign-up and login screens can show has its own text. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36], application = Application::class)
class AccountProblemTextUiTest {
    @get:Rule val rule = createEmptyComposeRule()
    private val ui = Ui(rule)
    private var problem by mutableStateOf<AccountProblem>(AccountProblem.Network)
    private val host = Host(rule) { Text(accountProblemText(problem)) }

    private fun shows(
        value: AccountProblem,
        expected: String,
    ) {
        rule.runOnIdle { problem = value }
        rule.waitForIdle()
        ui.see(expected)
    }

    @Test
    fun `each problem maps to its text, with the wait time as m ss when known`() {
        host.start(Screen.COVER)
        ui.see(string(R.string.fail_network))
        shows(AccountProblem.SignupDisabled, string(R.string.problem_signup_disabled))
        shows(AccountProblem.EmailTaken, string(R.string.problem_email_taken))
        shows(AccountProblem.InvalidCode, string(R.string.wrong_code))
        shows(AccountProblem.WrongPassword, string(R.string.fail_secret))
        shows(AccountProblem.LanOnly, string(R.string.fail_lan))
        shows(AccountProblem.Unexpected, string(R.string.problem_unexpected))
        shows(AccountProblem.Server("boom"), string(R.string.fail_server_code, "boom"))
        shows(AccountProblem.AccountLocked(75), string(R.string.problem_locked, "01:15"))
        shows(AccountProblem.AccountLocked(null), string(R.string.problem_locked_later))
        shows(AccountProblem.RateLimited(5), string(R.string.problem_rate_limited, "00:05"))
        shows(AccountProblem.RateLimited(0), string(R.string.problem_rate_limited_later))
    }
}
