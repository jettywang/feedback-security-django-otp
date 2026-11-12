# -*- coding: utf-8 -*-
"""
django-otp 1.7.5 状态机复现脚本（HOTP / TOTP）。

目的：用固定时钟和固定测试向量，重现“正常同步”与“需要重新配对”两类结果，
让支持同事看到 counter / tolerance / drift / last_t / 节流计数如何变化。

安全约定：
  * 不连接数据库：实例化后把 save() 替换为空操作，仅在内存里驱动真实模型代码；
  * 不打印任何密钥。脚本使用 RFC 4226/6238 公开测试向量，仅用于本地演示，
    绝不可用于生产设备；报告中只出现虚构设备，不记录 key；
  * 用户名/设备名均为虚构（example.com / example.net 保留域名）。

运行：.venv/bin/python diagnostics/otp_state_demo.py
"""
import django
from django.conf import settings

settings.configure(
    DEBUG=True,
    DATABASES={},  # 显式不使用数据库
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django_otp",
        "django_otp.plugins.otp_hotp",
        "django_otp.plugins.otp_totp",
    ],
    # 主体场景关闭指数退避，避免演示被节流打断；节流单独用一节展示
    OTP_HOTP_THROTTLE_FACTOR=0,
    OTP_TOTP_THROTTLE_FACTOR=0,
    OTP_TOTP_SYNC=True,
    USE_TZ=True,
)
django.setup()

from datetime import timedelta

from django.test import override_settings
from django.utils import timezone

from django_otp.oath import hotp
from django_otp.plugins.otp_hotp.models import HOTPDevice
from django_otp.plugins.otp_totp import models as totp_models
from django_otp.plugins.otp_totp.models import TOTPDevice

# RFC 4226/6238 公开测试向量（非生产密钥），脚本内仅用于生成示例令牌。
RFC_TEST_KEY = b"12345678901234567890"
RFC_TEST_KEY_HEX = RFC_TEST_KEY.hex()

# 固定“现在”：取一个能被 30 整除的 Unix 时间，保证 TOTP 时间步边界确定。
BASE_EPOCH = 1_700_000_040  # 当前服务端时间步 t_now = BASE_EPOCH // 30


def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def hotp_snapshot(device, tag):
    print(
        f"  [{tag}] counter={device.counter:<3} tolerance={device.tolerance} "
        f"fail_count={device.throttling_failure_count} "
        f"last_used_at={'set' if device.last_used_at else 'null'}"
    )


def totp_snapshot(device, tag):
    print(
        f"  [{tag}] drift={device.drift:<3} last_t={device.last_t:<3} "
        f"tolerance={device.tolerance} "
        f"fail_count={device.throttling_failure_count} "
        f"last_used_at={'set' if device.last_used_at else 'null'}"
    )


def make_hotp(name, counter=0, tolerance=5):
    device = HOTPDevice(
        user_id=900001, name=name, key=RFC_TEST_KEY_HEX, digits=6,
        tolerance=tolerance, counter=counter,
    )
    device.save = lambda *a, **k: None  # 不落库
    return device


def make_totp(name, tolerance=1, drift=0, last_t=-1):
    device = TOTPDevice(
        user_id=900002, name=name, key=RFC_TEST_KEY_HEX, step=30, t0=0,
        digits=6, tolerance=tolerance, drift=drift, last_t=last_t,
    )
    device.save = lambda *a, **k: None  # 不落库
    return device


def attempt(device, token, label, clock=None):
    """提交一次令牌；TOTP 可选固定时钟。返回 verify_token 的布尔结果。"""
    if isinstance(device, TOTPDevice) and clock is not None:
        original = totp_models.time.time
        totp_models.time.time = lambda: clock
        try:
            ok = device.verify_token(token)
        finally:
            totp_models.time.time = original
    else:
        ok = device.verify_token(token)
    print(f"  -> 提交令牌 {token:06d}（{label}）：{'接受' if ok else '拒绝'}")
    return ok


def totp_at(step_index):
    """模拟令牌 App 在某个绝对时间步上显示的码（不含设备自身漂移）。"""
    return hotp(RFC_TEST_KEY, step_index)


# ---------------------------------------------------------------------------
# 第一部分：HOTP（事件型，计数器驱动）
# ---------------------------------------------------------------------------
banner("第一部分 HOTP：counter / tolerance 如何更新（虚构设备 HOTP-FIC-001）")

print("\n场景 A 正常同步：设备按顺序出码，服务端在容差窗口内追上计数器")
hotp_a = make_hotp("HOTP-FIC-001", counter=0, tolerance=5)
hotp_snapshot(hotp_a, "初始")
token_c2 = hotp(RFC_TEST_KEY, 2)  # 设备连按 3 次，当前显示 counter=2 的码
attempt(hotp_a, token_c2, "设备显示 counter=2 的码，服务端还停在 0")
hotp_snapshot(hotp_a, "接受后")
print("     规则：命中 counter=2 后，服务端 counter 直接跳到 2+1=3（一次性补齐）")

token_c3 = hotp(RFC_TEST_KEY, 3)
attempt(hotp_a, token_c3, "下一个码 counter=3，正好等于服务端预期")
hotp_snapshot(hotp_a, "再接受后")

print("\n场景 B 重放保护：同一个 HOTP 码不能再用第二次（计数器只增）")
attempt(hotp_a, token_c3, "重复提交上一个已接受的码")
hotp_snapshot(hotp_a, "重放被拒后")

print("\n场景 C 超出容差：设备被按得太多，偏移超过 tolerance，同步失败")
hotp_c = make_hotp("HOTP-FIC-002", counter=10, tolerance=5)
hotp_snapshot(hotp_c, "初始，服务端 counter=10，tolerance=5 -> 窗口 10..15")
token_far = hotp(RFC_TEST_KEY, 20)  # 设备计数器走到 20，超出 10..15
attempt(hotp_c, token_far, "设备码对应 counter=20，落在窗口外")
hotp_snapshot(hotp_c, "拒绝后，counter 保持不变")
print("     规则：窗口内无匹配 => counter 不动，失败只累加节流计数。")
print("     HOTP 无自动重对齐：要么人工把 counter 校到设备附近，要么重新配对。")

print("\n场景 D 设备计数器反而落后于服务端（常见于换设备/设备被重置）")
hotp_d = make_hotp("HOTP-FIC-003", counter=8, tolerance=5)
hotp_snapshot(hotp_d, "服务端 counter=8 -> 窗口 8..13，只会向更大值找")
token_behind = hotp(RFC_TEST_KEY, 4)  # 被重置的设备从更小计数器出码
attempt(hotp_d, token_behind, "设备码对应 counter=4，小于服务端 counter")
hotp_snapshot(hotp_d, "拒绝后")
print("     规则：range 只从 self.counter 向上找，旧计数器无法把服务端拉回；")
print("     两侧已不是同一条计数序列，通常意味着密钥/设备不一致，需重新配对。")

# ---------------------------------------------------------------------------
# 第二部分：TOTP（时间型，drift / last_t 驱动）
# ---------------------------------------------------------------------------
banner("第二部分 TOTP：tolerance / drift / last_t 如何更新（虚构设备 TOTP-FIC-101）")

t_now = BASE_EPOCH // 30
print(f"\n固定时钟：epoch={BASE_EPOCH}，当前服务端时间步 t_now={t_now}，step=30s")

print("\n场景 A 正常同步：设备时钟慢 1 步，容差=1 内命中并自动学习 drift")
totp_a = make_totp("TOTP-FIC-101", tolerance=1, drift=0, last_t=-1)
totp_snapshot(totp_a, "初始")
slow_token = totp_at(t_now - 1)  # 设备慢一拍，显示上一时间步的码
attempt(totp_a, slow_token, "设备慢 1 步显示的码", clock=BASE_EPOCH)
totp_snapshot(totp_a, "接受后")
print("     规则：TOTP.verify 用 drift+offset 命中后，drift 更新为 -1，")
print("     last_t 更新为命中的时间步；之后即便 tolerance 调小也能对上。")

clock_next = BASE_EPOCH + 30
next_slow_token = totp_at((t_now + 1) - 1)  # 设备仍慢 1 步
totp_a.tolerance = 0  # 学会漂移后不再依赖容差窗口
attempt(totp_a, next_slow_token, "30 秒后新码，drift 已记住慢 1 步", clock=clock_next)
totp_snapshot(totp_a, "再接受后")

print("\n场景 B 重放保护：同一时间步的码不能用两次（last_t 只接受更大的 t）")
replay = attempt(totp_a, next_slow_token, "重复提交刚用过的同一步码", clock=clock_next)
totp_snapshot(totp_a, "重放被拒后，last_t 不变")
assert replay is False

print("\n场景 C 客户现场：校准 drift 后“立刻”仍失败——last_t 卡住当前步")
totp_c = make_totp("TOTP-FIC-102", tolerance=1, drift=-1, last_t=t_now - 1)
totp_snapshot(totp_c, "上次成功登录：drift=-1，last_t 停在被接受的时间步")
# 支持把设备时钟校准回与服务端一致：drift 归 0。注意这不会触碰 last_t。
totp_c.drift = 0
old_token = totp_at(t_now - 1)  # 用户手上还是校准前那一窗口的旧码
attempt(totp_c, old_token, "同一窗口内用校准前的旧码立即重试", clock=BASE_EPOCH)
totp_snapshot(totp_c, "被拒：该 t 已 <= last_t，drift 改对了也没用")
print("     关键：重新校准只改 drift，不会回退 last_t。需等到下一个 30 秒窗口，")
print("     用新时间步（t > last_t）的码提交才能恢复——这就是‘不能立即恢复’。")
clock_after = BASE_EPOCH + 30
fresh_token = totp_at(t_now + 1)  # 时钟已对齐，设备显示服务端下一步的码
attempt(totp_c, fresh_token, "等到下一窗口，用新码提交", clock=clock_after)
totp_snapshot(totp_c, "接受后恢复正常")

print("\n场景 D 超出容差：设备时钟偏移 >= 2 步，tolerance=1 无法覆盖，需重新配对")
totp_d = make_totp("TOTP-FIC-103", tolerance=1, drift=0, last_t=-1)
totp_snapshot(totp_d, "初始，窗口仅覆盖 t-1..t+1")
far_slow_token = totp_at(t_now - 2)  # 设备慢 2 步
attempt(totp_d, far_slow_token, "设备慢 2 步的码，超出 ±1 容差", clock=BASE_EPOCH)
totp_snapshot(totp_d, "拒绝：drift 保持 0，last_t 保持 -1，状态完全没动")
print("     规则：TOTP.verify 遍历完容差区间都不匹配时会把 drift 还原；")
print("     OTP_TOTP_SYNC 只能在容差内学习，偏出容差永远学不会，需重新配对/纠正时钟。")

print("\n场景 E OTP_TOTP_SYNC=False：可凭容差临时通过，但不学习漂移，问题会反复")
totp_e = make_totp("TOTP-FIC-104", tolerance=1, drift=0, last_t=-1)
with override_settings(OTP_TOTP_SYNC=False):
    attempt(totp_e, slow_token, "设备慢 1 步，容差内可通过", clock=BASE_EPOCH)
totp_snapshot(totp_e, "接受但 drift 仍为 0（未学习），换个时刻仍可能失败")
print("     规则：SYNC 关闭时 verify_token 不回写 drift，靠容差兜底而非真正对齐。")

# ---------------------------------------------------------------------------
# 第三部分：节流（指数退塞）如何叠加在上述状态机之上
# ---------------------------------------------------------------------------
banner("第三部分 节流 ThrottlingMixin：失败计数与退避（两种设备逻辑相同）")

throttle_device = make_hotp("HOTP-FIC-004", counter=0, tolerance=5)
# 打开节流（主体演示里 factor=0 是关闭的）
throttle_device.get_throttle_factor = lambda: 1
throttle_device.__dict__.pop("throttling_enabled", None)  # 清掉可能的缓存
throttle_device.throttling_enabled = True

print("\n连续错误码累积 failure_count，并产生指数退避 1,2,4,8... 秒")
print("（演示中把失败时间戳回拨，模拟每个退避窗口已过，从而连续触发计数累加）")
for n in range(1, 4):
    # 回拨到足够久以前，确保 verify_is_allowed 放行，真正进入校验并累加计数
    throttle_device.throttling_failure_timestamp = timezone.now() - timedelta(seconds=60)
    attempt(throttle_device, hotp(RFC_TEST_KEY, 99), "错误码（故意不匹配）")
    required = 1 * (2 ** (throttle_device.throttling_failure_count - 1))
    print(
        f"     失败后 failure_count={throttle_device.throttling_failure_count}，"
        f"下次提交需等待 {required} 秒（factor=1 的 2^(n-1) 退避）"
    )

print("\n处于退避窗口内时，verify_is_allowed 直接拦截，连校验都不会进入：")
allowed, info = throttle_device.verify_is_allowed()
print(
    f"     verify_is_allowed -> {'允许' if allowed else '拒绝'}，"
    f"failure_count={info['failure_count']}，"
    f"locked_until={info['locked_until'].strftime('%H:%M:%S')}"
)

print("\n退避窗口过去后令牌正确，一次成功即清零失败计数与时间戳：")
throttle_device.throttling_failure_timestamp = timezone.now() - timedelta(seconds=30)
allowed, _ = throttle_device.verify_is_allowed()
print(f"     退避窗口过后 verify_is_allowed -> {'允许' if allowed else '仍拒绝'}")
good = hotp(RFC_TEST_KEY, throttle_device.counter)
attempt(throttle_device, good, "窗口过后提交正确码")
hotp_snapshot(throttle_device, "成功后 fail_count 清零、时间戳置空")

print("\n" + "=" * 72)
print("演示结束：全程未连接数据库、未打印密钥；设备/用户均为虚构。")
print("=" * 72)
