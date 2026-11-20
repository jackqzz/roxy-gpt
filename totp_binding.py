"""Durable, resumable TOTP binding without importing the application server.

HTTP hooks receive a zero-argument callable, so callers can reuse their existing
Cloudflare retry wrapper. ``persist(account)`` must synchronously save the account
or raise; an explicit False return is also treated as failure. No response body,
credential, enrollment session or generated code is included in logs/results.
"""
import base64
import hashlib
import hmac
import re
import struct
import time


_INACTIVE = frozenset(('pending', 'disabled', 'inactive', 'unverified',
                       'unconfirmed', 'not_enabled', 'not_verified', 'unenrolled',
                       'revoked', 'deleted', 'expired', 'failed', 'awaiting_verification',
                       'pending_verification', 'pending_activation'))
_ACTIVE = frozenset(('active', 'enabled', 'verified', 'confirmed', 'configured',
                     'enrolled', 'complete', 'completed'))
_FALSE = frozenset(('', '0', 'false', 'off', 'none', 'null', 'no'))
_PENDING = frozenset(('pending', 'unverified', 'unconfirmed', 'awaiting_verification',
                      'pending_verification', 'pending_activation'))


def _text(value):
    return value.strip() if isinstance(value, str) else ''


def _normal(value):
    return str(value).strip().lower().replace('-', '_').replace(' ', '_')


def _factor_active(factor):
    if not isinstance(factor, dict) or not factor:
        return False
    kind = _text(factor.get('factor_type') or factor.get('type')).lower()
    if kind and kind != 'totp':
        return False
    positive = False
    # Metadata can carry explicit lifecycle state even when the top level lacks it.
    metadata = factor.get('metadata')
    containers = (factor, metadata) if isinstance(metadata, dict) else (factor,)
    for values in containers:
        for key in ('enabled', 'verified', 'is_enabled'):
            if key in values:
                value = values[key]
                if value is None or _normal(value) in _FALSE:
                    return False
                if value is not True and _normal(value) not in ('1', 'true', 'on', 'yes'):
                    return False
                positive = True
        for key in ('disabled', 'pending', 'is_pending'):
            if key in values and _normal(values[key]) not in _FALSE:
                return False
        for key in ('status', 'state', 'enrollment_status'):
            if key in values:
                state = _normal(values[key])
                if state in _INACTIVE or state not in _ACTIVE:
                    return False
                positive = True
    # The observed configured shape has an ID but no enabled/verified field.
    return positive or bool(_text(factor.get('id')))


def _totp_factors(info):
    """Return factor objects and whether any nonempty TOTP evidence exists."""
    if not isinstance(info, dict):
        return [], False
    factors = info.get('factors')
    if isinstance(factors, dict):
        value = factors.get('totp')
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)], bool(value)
        if isinstance(value, dict):
            return ([value] if value else []), bool(value)
        return [], bool(value)
    if isinstance(factors, list):
        values = [item for item in factors if isinstance(item, dict)
                  and _text(item.get('factor_type') or item.get('type')).lower() == 'totp']
        return values, bool(values)
    return [], False


def totp_present(info):
    """Whether any TOTP factor has a configured, nonpending/non-disabled state."""
    return any(_factor_active(factor) for factor in _totp_factors(info)[0])


def _factor_resumable(factor):
    metadata = factor.get('metadata')
    containers = (factor, metadata) if isinstance(metadata, dict) else (factor,)
    for values in containers:
        if 'disabled' in values and _normal(values['disabled']) not in _FALSE:
            return False
        for key in ('status', 'state', 'enrollment_status'):
            if key in values and _normal(values[key]) not in _PENDING:
                return False
    return True


def _readback_propagating(info, factor_id):
    """Retry only absent factors or the same factor explicitly awaiting activation."""
    factors, evidence = _totp_factors(info)
    if not evidence:
        return True
    if not factors:
        return False
    for factor in factors:
        if _text(factor.get('id')) != factor_id or not _factor_resumable(factor):
            return False
        kind = _text(factor.get('factor_type') or factor.get('type')).lower()
        if kind and kind != 'totp':
            return False
        metadata = factor.get('metadata')
        containers = (factor, metadata) if isinstance(metadata, dict) else (factor,)
        pending = any(
            (key in values and _normal(values[key]) in _PENDING)
            for values in containers for key in ('status', 'state', 'enrollment_status'))
        pending = pending or any(
            (key in values and _normal(values[key]) in ('1', 'true', 'on', 'yes'))
            for values in containers for key in ('pending', 'is_pending'))
        if not pending:
            return False
    return True


class _BindingError(Exception):
    def __init__(self, code, detail):
        self.code = code
        self.detail = detail


def _default_code(secret):
    raw = re.sub(r'\s+', '', secret).upper()
    key = base64.b32decode(raw + '=' * (-len(raw) % 8))
    counter = struct.pack('>Q', int(time.time() // 30))
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return '%06d' % (value % 1000000)


def bind_totp(session, at, account, log, *,
              base_url='https://chatgpt.com/backend-api/accounts',
              persist=None, should_stop=None, request=None,
              generate_code=None, now=None, sleep=None):
    """Return ``(ok, ''|'at_expired'|'reauth'|'other', safe_detail)``.

    A saved ``totp_enrollment`` resumes its original activation session. An
    existing server factor is only reconciled when its ID and the local secret
    agree. New secrets are persisted before activation, including when stopping.
    Readback permits three observations with at most two one-second waits for
    factor propagation. ``sleep(seconds)`` can replace ``time.sleep`` in tests.
    """
    account['totp_ok'] = False
    headers = {'authorization': 'Bearer ' + at, 'content-type': 'application/json'}
    runner = request if request is not None else lambda fn: fn()
    code_generator = generate_code if generate_code is not None else _default_code
    clock = now if now is not None else lambda: time.strftime('%Y-%m-%dT%H:%M:%S')
    pause = sleep if sleep is not None else time.sleep

    def stopped():
        if should_stop is not None and should_stop():
            raise _BindingError('other', 'TOTP 已停止')

    def emit(message):
        # Logging must not turn an already-enrolled secret into an unsaved one.
        if log is not None:
            try:
                log(message)
            except Exception:
                pass

    def save():
        if persist is None:
            raise _BindingError('other', 'TOTP 缺少 persist，无法持久化')
        try:
            saved = persist(account)
        except Exception:
            raise _BindingError('other', 'TOTP persist 失败') from None
        if saved is False:
            raise _BindingError('other', 'TOTP persist 失败')

    def send(method, path, stage, payload=None):
        def invoke():
            if method == 'POST':
                stopped()  # Also checked on each retry performed by request(fn).
                return session.post(base_url.rstrip('/') + path,
                                    headers=headers, json=payload)
            return session.get(base_url.rstrip('/') + path, headers=headers)
        if method == 'POST':
            stopped()
        try:
            response = runner(invoke)
            status = int(response.status_code)
        except _BindingError:
            raise
        except Exception:
            raise _BindingError('other', stage + ' 请求失败') from None
        if status == 401:
            try:
                body = (response.text or '').lower()
            except Exception:
                body = ''
            needs_reauth = any(mark in body for mark in ('re-auth', 'reauth', 're_auth'))
            raise _BindingError('reauth' if needs_reauth else 'at_expired',
                                stage + ' HTTP 401')
        if status != 200:
            raise _BindingError('other', stage + ' HTTP %d' % status)
        return response

    def read_info(stage):
        response = send('GET', '/mfa_info', stage)
        try:
            info = response.json()
        except Exception:
            raise _BindingError('other', stage + ' 响应无效') from None
        if not isinstance(info, dict):
            raise _BindingError('other', stage + ' 响应无效')
        factors = info.get('factors')
        if factors is not None and not isinstance(factors, (dict, list)):
            raise _BindingError('other', stage + ' factors 响应无效')
        if isinstance(factors, list) and any(not isinstance(value, dict) for value in factors):
            raise _BindingError('other', stage + ' factors 响应无效')
        return info

    def confirm():
        previous_pending = account.get('totp_enrollment')
        had_pending = 'totp_enrollment' in account
        previous_time = account.get('totp_at')
        had_time = 'totp_at' in account
        try:
            timestamp = clock()
        except Exception:
            raise _BindingError('other', 'TOTP 确认时间生成失败') from None
        account['totp_ok'] = True
        account['totp_at'] = timestamp
        account.pop('totp_enrollment', None)
        try:
            save()
        except _BindingError:
            account['totp_ok'] = False
            if had_pending:
                account['totp_enrollment'] = previous_pending
            if had_time:
                account['totp_at'] = previous_time
            else:
                account.pop('totp_at', None)
            raise
        emit('  TOTP 已复核并持久化')
        return True, '', 'TOTP 已确认'

    try:
        stopped()
        info = read_info('mfa_info')
        factors, server_has_factor = _totp_factors(info)
        active = [factor for factor in factors if _factor_active(factor)]
        secret = _text(account.get('totp'))
        factor_id = _text(account.get('totp_id'))
        if active:
            if secret and factor_id and any(_text(factor.get('id')) == factor_id
                                           for factor in active):
                return confirm()
            raise _BindingError('other', '服务端已有 TOTP，本地 secret 或 factor ID 无法核对，已保留')

        pending = account.get('totp_enrollment')
        if pending is not None:
            if not isinstance(pending, dict):
                raise _BindingError('other', 'TOTP 待激活记录无效，已保留')
            session_id = _text(pending.get('session_id'))
            pending_id = _text(pending.get('factor_id'))
            if not (secret and factor_id and session_id and pending_id == factor_id):
                raise _BindingError('other', 'TOTP 待激活记录不完整或 factor ID 冲突，已保留')
            if server_has_factor:
                # Only an unambiguously matching pending factor can be resumed.
                ids = [_text(factor.get('id')) for factor in factors]
                if (not ids or any(value != factor_id for value in ids)
                        or any(not _factor_resumable(factor) for factor in factors)):
                    raise _BindingError('other', '服务端 TOTP factor ID 无法核对，已保留')
            save()
        else:
            if server_has_factor:
                raise _BindingError('other', '服务端 TOTP 状态未确认，已保留且未重新 enroll')
            if secret or factor_id:
                raise _BindingError('other', '本地 TOTP 无可恢复的待激活记录，已保留')
            if persist is None:
                raise _BindingError('other', 'TOTP 缺少 persist，无法持久化')
            response = send('POST', '/mfa/enroll', 'enroll', {'factor_type': 'totp'})
            try:
                enrolled = response.json()
            except Exception:
                raise _BindingError('other', 'enroll 响应无效') from None
            if not isinstance(enrolled, dict):
                raise _BindingError('other', 'enroll 响应无效')
            secret = _text(enrolled.get('secret'))
            session_id = _text(enrolled.get('session_id'))
            factor = enrolled.get('factor')
            factor_id = _text(factor.get('id')) if isinstance(factor, dict) else ''
            if not secret:
                raise _BindingError('other', 'enroll 缺少 secret')
            account['totp'] = secret
            account['totp_id'] = factor_id
            account['totp_enrollment'] = {'session_id': session_id, 'factor_id': factor_id}
            # Never inspect the stop signal between receiving and saving a secret.
            save()
            if not session_id or not factor_id:
                raise _BindingError('other', 'enroll 缺少 session_id 或 factor ID，secret 已保存')

        stopped()
        try:
            code = code_generator(secret)
        except Exception:
            raise _BindingError('other', 'TOTP 验证码生成失败') from None
        if not isinstance(code, str) or re.fullmatch(r'[0-9]{6}', code) is None:
            raise _BindingError('other', 'TOTP 验证码生成失败')
        send('POST', '/mfa/user/activate_enrollment', 'activate',
             {'code': code, 'factor_type': 'totp', 'session_id': session_id})
        for attempt in range(3):
            stopped()
            verified = read_info('mfa_info 复核')
            stopped()
            if any(_text(factor.get('id')) == factor_id and _factor_active(factor)
                   for factor in _totp_factors(verified)[0]):
                return confirm()
            if attempt == 2 or not _readback_propagating(verified, factor_id):
                break
            stopped()
            try:
                pause(1.0)
            except Exception:
                raise _BindingError('other', 'TOTP 复核等待失败，secret 已保留') from None
        raise _BindingError('other', 'TOTP 复核未确认同一 factor ID 已启用，secret 已保留')
    except _BindingError as exc:
        emit('  ' + exc.detail)
        return False, exc.code, exc.detail
    except Exception:
        emit('  TOTP 操作失败，未确认成功')
        return False, 'other', 'TOTP 操作失败，未确认成功'
