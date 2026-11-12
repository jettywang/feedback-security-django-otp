# Feedback task starting environment

Upstream: https://github.com/django-otp/django-otp
Upstream commit: `1c77c58f6785b49da3250b01dedbbc77ed0429ae`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m django test django_otp.tests.OTPMiddlewareTestCase django_otp.tests.OTPAuthenticationFormDeviceRequiredTestCase django_otp.plugins.otp_email.tests.EmailTest --settings=test_project.settings --pythonpath=test --noinput
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `Destroying test database for alias 'default'...`
Whole-command wall time: 3.999 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
