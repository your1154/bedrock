# 코드 리뷰 리포트

## index.php (219줄)

### 스타일 검사
검색 결과에 PHP 코드 스타일 가이드 정보가 없어 스타일 관점의 검사는 제공할 수 없습니다. 그러나 검색 결과에 포함된 OWASP Top 10 기준으로 해당 PHP 코드의 보안 취약점은 다음과 같이 분석할 수 있습니다.

---

## OWASP 기준 보안 취약점 분석

### 🔴 A03:2021 – Injection (인젝션)
- **DB 모드**에서 `rand()` 결과를 직접 SQL 쿼리에 삽입하고 있으며, Prepared Statement를 사용하지 않고 있습니다.
- 현재 코드: `"INSERT INTO load_logs (log_data) VALUES ('L_" . rand() . "')"` — 비록 `rand()`는 안전하지만, 이 패턴은 외부 입력값이 들어올 경우 SQL Injection에 취약한 구조입니다.

### 🔴 A01:2021 – Broken Access Control (접근 제어 오류)
- `$_GET['mode']` 파라미터에 대한 입력값 검증이 미흡합니다. `switch` 문에서 `default`로 처리되긴 하지만, 명시적인 허용 목록(whitelist) 검증이 없습니다.
- 누구나 `?mode=reset_connection`을 호출해 세션을 파괴하고 쿠키를 삭제할 수 있습니다. 인증/인가 없이 서버 세션을 조작할 수 있는 문제가 있습니다.

### 🔴 A05:2021 – Security Misconfiguration (보안 설정 오류)
- `db_config.php`가 없을 경우, `$db_pass = ''`(빈 패스워드)와 `$db_user = 'root'`가 기본값으로 사용됩니다. 이는 매우 위험한 기본 설정입니다.
- DB 연결 오류 메시지(`$conn->connect_error`)가 그대로 화면에 출력되어 내부 시스템 정보가 노출됩니다.

### 🟡 A02:2021 – Cryptographic Failures (암호화 오류)
- 세션 및 쿠키를 단순 삭제 처리하며, Secure/HttpOnly 플래그 없이 쿠키를 설정합니다.
- `setcookie('AWSALB', '', time() - 3600, '/')` — `secure`, `httponly` 옵션이 누락되었습니다.

### 🟡 A09:2021 – Security Logging and Monitoring Failures (로깅 오류)
- 의도적 500 에러 발생 시에만 `error_log()`를 호출하며, DB 연결 실패, 비정상 접근 등 다른 중요한 이벤트에 대한 로깅이 없습니다.

### 🟠 XSS (출력값 이스케이프 미흡)
- `echo $server_ip`, `echo $current_az`, `echo $message`, `echo $extra_info` 등 HTML 출력 시 `htmlspecialchars()`를 사용하지 않아 XSS 공격에 노출될 수 있습니다.

---

> ⚠️ PHP 코드 스타일(PSR-1, PSR-12 등) 관점의 검사는 검색 결과에 해당 가이드가 포함되어 있지 않아 제공이 어렵습니다.

### 보안 검사
코드 분석 결과, 요청하신 3가지 항목(SQL Injection, XSS, 하드코딩된 비밀번호) 및 추가 취약점을 아래와 같이 정리합니다.

---

## 1. ❌ XSS (Cross-Site Scripting) — 심각도: **높음**

**위치 (복수):**
- `<?php echo $server_ip; ?>` — `$metadata['ip']`가 직접 출력됨
- `<?php echo $current_az; ?>` — `$metadata['az']`가 직접 출력됨
- `<?php echo $badge_class; ?>` — CSS 클래스로 삽입됨
- `<?php echo $message; ?>` — `$extra_info`와 함께 직접 출력됨
- `<?php echo $extra_info; ?>` — DB 오류 메시지 포함 가능

**설명:**
출력 시 `htmlspecialchars()`와 같은 이스케이프 처리가 전혀 없습니다. 특히 `$server_ip`, `$current_az`는 외부 메타데이터나 서버 변수에서 오는 값이므로, 조작된 환경에서 악성 스크립트가 삽입될 수 있습니다.

**수정 제안:**
```php
echo htmlspecialchars($server_ip, ENT_QUOTES, 'UTF-8');
echo htmlspecialchars($current_az, ENT_QUOTES, 'UTF-8');
echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
echo htmlspecialchars($extra_info, ENT_QUOTES, 'UTF-8');
```

---

## 2. ❌ Open Redirect — 심각도: **중간**

**위치:**
```php
header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
```

**설명:**
`$_SERVER["REQUEST_URI"]`는 클라이언트가 조작 가능한 값입니다. 특정 웹서버 환경에서 `//evil.com/path` 형태로 오픈 리다이렉트가 가능할 수 있습니다.

**수정 제안:**
```php
$safe_path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
header("Location: " . $safe_path);
```

---

## 3. ⚠️ DB 연결 정보 폴백 하드코딩 — 심각도: **낮음~중간**

**위치:**
```php
$db_host = 'localhost'; $db_user = 'root'; $db_pass = ''; $db_name = 'test';
```

**설명:**
`db_config.php`가 없을 경우 `root` 계정과 빈 패스워드로 DB에 연결을 시도합니다. 프로덕션 환경에서 `db_config.php`가 누락되면 보안이 취약한 기본값으로 실행됩니다. SQL Injection 자체는 이 코드에서 발견되지 않았으나(쿼리에 사용자 입력값이 직접 사용되지 않음), `root` 계정 사용은 DB 전체 권한 탈취 위험이 있습니다.

**수정 제안:**
- 폴백 하드코딩 제거, `db_config.php` 없을 시 명시적 오류 처리
- 최소 권한 원칙의 DB 계정 사용

---

## 4. ⚠️ DB 오류 메시지 노출 — 심각도: **중간**

**위치:**
```php
$extra_info = $conn->connect_error;
...
echo $extra_info;
```

**설명:**
DB 연결 실패 시 내부 오류 메시지가 그대로 화면에 출력됩니다. 이는 DB 호스트 정보, 구조 등 민감한 정보를 공격자에게 노출할 수 있습니다. (OWASP A05: Security Misconfiguration 해당)

**수정 제안:**
```php
// 사용자에게는 일반 메시지만 표시
$extra_info = "DB 연결에 실패했습니다.";
// 내부 로그에만 기록
error_log($conn->connect_error);
```

---

## 5. ✅ SQL Injection — **해당 없음**

DB 모드에서 사용자 입력값이 쿼리에 직접 삽입되지 않고 `rand()`만 사용하므로, 현재 코드에서 SQL Injection 취약점은 발견되지 않습니다.

---

## 요약 테이블

| # | 유형 | 위치 | 심각도 |
|---|------|------|--------|
| 1 | XSS | echo $server_ip, $current_az, $message 등 | 높음 |
| 2 | Open Redirect | header("Location: " . REQUEST_URI) | 중간 |
| 3 | 하드코딩 폴백 자격증명 | $db_user = 'root', $db_pass = '' | 중간 |
| 4 | DB 오류 메시지 노출 | echo $conn->connect_error | 중간 |
| 5 | SQL Injection | 해당 없음 | — |

---

