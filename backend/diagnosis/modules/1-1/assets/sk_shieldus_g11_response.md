해당 취약점을 예방할 수 있는 최선의 방안은 모든 코드들을 상세히 검증하는 것입니다.
즉, 헤더, 쿠키, 질의문, 폼필드와 숨겨진 필드 등과 같은 모든 파라미터들을 엄격한 규칙에 의해서 검증합니다.

1. 입력값 검증 및 특수문자 변환

다음과 같이 왼쪽 필드의 입력 데이터를 오른쪽 필드로 변환하여 필터링해야 합니다.

| From | To(숫자표현) | To(문자표현) |
|---|---|---|
| < | &#60; | &lt; |
| > | &#62; | &gt; |
| ( | &#40; | - |
| ) | &#41; | - |
| # | &#35; | - |
| & | &#38; | &amp; |
| ‘ | &#39; | - |
| “ | &#34; | &quot; |

2. Positive 필터링 권고

HTML에 있는 모든 메타 캐릭터의 제거가 힘들 경우, 허용하는 문자들(e.g. [A-Za-z0-9])만 사용되도록 하고 이외의 것은 배제하는 형태인 positive 필터링 모드를 사용하는 것을 권고합니다.

3. XSS Keyword 필터링

사이트 내 태그 사용이 불가피한 경우, 아래 Keyword를 사용하지 못하도록 필터링하여 XSS 구문 공격에 대한 최소한의 대응을 해야 합니다.

주의사항:
- 패스워드 등록/변경 또는 로그인 시 패스워드 정책에 따라 특수문자 사용이 필요한 경우, 필터링 적용에 대한 검토가 필요합니다.
- Keyword 필터링은 대/소문자 구분 없이 적용해야 합니다.
- 일괄 적용 시 오류가 발생할 수 있으므로 서비스 및 운영상의 영향도를 확인한 뒤 적용해야 합니다.

대표 XSS Keyword 필터링 문자열:

스크립트/프로토콜:
`<script>`, `javascript`, `%3Cscript`, `JaVaScRiPt`, `ScRiPt%20%0a%0d`, `script`, `vbscript`, `expression`, `eval`, `innerHTML`, `document`, `cookie`, `href`

HTML/임베드 태그:
`applet`, `meta`, `xml`, `blink`, `link`, `style`, `embed`, `object`, `iframe`, `frame`, `frameset`, `background`, `layer`, `ilayer`, `bgsound`, `title`, `base`, `video`, `audio`, `details`

경고/실행/우회 키워드:
`%3Ealert`, `alert`, `msgbox`, `@import`, `+ADw`, `+AD4`, `aim:`, `%0da=eval`, `http-equiv=refresh`, `list-style-image`, `x-scriptlet`, `echo(`, `moz-binding`, `res://`, `#exec`, `%u0`, `&#x`, `fromcharcode`, `firefoxurl`, `wvs-xss`, `acunetix_wvs`

브라우저/플러그인 객체:
`behavior`, `activexobject`, `microsoft.xmlhttp`, `clsid:cafeefac-dec7-0000-0000-abcdeffedcba`, `application/npruntime-scriptable-plugin`, `deploymenttoolkit`, `java.lang.Runtime`, `getRuntime`

이벤트 핸들러:
`onload`, `onclick`, `onerror`, `onmouseover`, `onmouseout`, `onmousedown`, `onmouseup`, `onmousemove`, `onmouseenter`, `onmouseleave`, `onkeydown`, `onkeypress`, `onkeyup`, `onfocus`, `onblur`, `onchange`, `onsubmit`, `onreset`, `onselect`, `onscroll`, `onresize`, `ondrag`, `ondrop`, `onpaste`, `oncopy`, `oncut`, `oninput`, `onwheel`, `onsearch`, `oninvalid`, `oncanplay`, `onplay`, `onplaying`, `onloadeddata`, `onloadedmetadata`, `onended`, `ontoggle`, `onpageshow`, `onpagehide`

4. AntiSamy 기반 허용 태그 정책

서비스 운영 시 특정 태그에 대한 사용이 필요한 경우, OWASP에서 제공하는 AntiSamy를 이용하여 허용할 태그 및 속성, CSS 값을 직접 정의하고 정의되지 않은 이외의 값은 필터링 처리하여 사용하도록 합니다.
해당 필터링은 `antisamy.xml` 파일의 정책에 기반하여 동작합니다.

참고:
- https://owasp.org/www-project-antisamy/
- https://github.com/nahsra/antisamy

JAVA 적용 필수파일:
- Policy File: `antisamy.xsd`, `antisamy.xml`
- Library File: `antisamy.jar`, `xercesImpl.jar`, `batik.jar`, `nekohtm.jar`

5. HttpOnly 쿠키 옵션 설정

추가적으로 서버가 생성하는 `Set-Cookie`에 `HttpOnly` 옵션이 있다면, JavaScript의 `document.cookie` 메소드를 통해 쿠키정보를 브라우저로 획득할 수 없습니다.
따라서 쿠키 생성 시 `HttpOnly` 옵션을 설정해야 합니다.

언어별 설정 예:
- ASP.NET: `httpCookies httpOnlyCookies="true" requireSSL="true"` 설정 또는 쿠키 생성 시 `cookie.HttpOnly = true`
- PHP: `php.ini`에 `session.cookie_httponly = True` 추가 및 `allow_url_include = off` 설정
- JAVA: `WEB-INF/web.xml`에 `<http-only>true</http-only>` 설정
- Node.js: 쿠키 설정 시 `httpOnly: true` 적용
