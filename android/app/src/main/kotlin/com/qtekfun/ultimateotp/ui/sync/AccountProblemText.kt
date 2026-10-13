// SPDX-FileCopyrightText: 2026 UltimateOTP contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package com.qtekfun.ultimateotp.ui.sync

import android.text.format.DateUtils
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.qtekfun.ultimateotp.R
import com.qtekfun.ultimateotp.core.sync.login.AccountProblem

/** What the sign-up and login screens say for a [problem]; `retry_after` shown as m:ss. */
@Composable
fun accountProblemText(problem: AccountProblem): String =
    when (problem) {
        AccountProblem.SignupDisabled -> {
            stringResource(R.string.problem_signup_disabled)
        }

        AccountProblem.EmailTaken -> {
            stringResource(R.string.problem_email_taken)
        }

        AccountProblem.InvalidCode -> {
            stringResource(R.string.wrong_code)
        }

        AccountProblem.WrongPassword -> {
            stringResource(R.string.fail_secret)
        }

        AccountProblem.LanOnly -> {
            stringResource(R.string.fail_lan)
        }

        AccountProblem.Network -> {
            stringResource(R.string.fail_network)
        }

        AccountProblem.Unexpected -> {
            stringResource(R.string.problem_unexpected)
        }

        is AccountProblem.Server -> {
            stringResource(R.string.fail_server)
        }

        is AccountProblem.AccountLocked -> {
            waitText(R.string.problem_locked, R.string.problem_locked_later, problem.retryAfterSeconds)
        }

        is AccountProblem.RateLimited -> {
            waitText(R.string.problem_rate_limited, R.string.problem_rate_limited_later, problem.retryAfterSeconds)
        }
    }

@Composable
private fun waitText(
    withTime: Int,
    withoutTime: Int,
    seconds: Long?,
): String =
    if (seconds != null && seconds > 0) {
        stringResource(withTime, DateUtils.formatElapsedTime(seconds))
    } else {
        stringResource(withoutTime)
    }
