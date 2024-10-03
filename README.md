# Spring Secuirty

## User (UsersDetail 구현 포함)

----- 

1. 인증 과정에서의 사용:
   - 사용자가 로그인하면 Spring Security는 UserDetailsService를 통해 UserDetails 객체를 로드
   - 이 때 UserDetails 인터페이스를 구현한 User 객체가 반환
2. 사용자 정보 검증:
   - getUsername() 과 getPassword() 를 사용하여 사용자 입력과 데이터베이스의 정보를 비교
   - 상태 메서드들을 호출하여 계정의 상태를 확인
3. 권한 부여:
   - getAuthorities() 를 통해 사용자에게 부여된 권한을 가져옴
   - Spring Security는 이 정보를 기반으로 사용자가 요청한 리소스에 접근할 수 있는지 판단

## JwtService

--- 

1. JWT 토큰 생성:
   - User가 로그인하면 generateToken() 를 호출하여 사용자 정보를 기반으로 JWT 토큰을 생성
   - 생성된 토큰은 클라이언트에게 전달되어 이후 인증이 필요한 요청 시 사용
2. JWT 토큰 검증:
   - 클라이언트로부터 요청이 들어오면 해당 요청에 포함된 토큰을 isValid 메서드를 통해 검증
   - 토큰의 서명을 검증하고 토큰이 만료되지 않았으며 토큰에 포함된 사용자 정보가 올바른지 확인
3. 클레임(Payload) 추출 및 활용
   - 인증 및 권한 부여 과정에서 필요한 정보를 얻기 위해 extractClaim, extractUsername, extractExpiration 등의 메서드 사용

## JwtAuthenticationFilter

---

1. 요청 헤더에서 Authorization Header 추출 -> 토큰 존재 확인
2. 토큰 추출 -> username 얻음
3. 현재 User 가 인증되지 않은 경우에만 다음단계 진행
4. 사용자 정보를 로드 -> 토큰의 유효성 검증
5. 토큰이 유효 -> 인증 객체 생성, SecurityContext 에 설정
6. FilterChain 을 계속 진행하여 요청 처리가 완료

- OncePerRequestFilter:
  - Spring 에서 제공하는 추상 클래스
  - 각 요청마다 단 한 번만 실행되는 필터를 만들기 위해 사용
  - doFilterInternal() 구현 -> 필터 로직 작성
- SecurityContextHolder:
  - Spring Security 에서 현재 실행 중인 스레드의 보안 컨텍스트를 저장하고 접근하는 데 사용
  - ***getContext().setAuthentication(Authentication authentication)*** 을 통해 인증 정보 설정
- UsernamePasswordAuthenticationToken:
  - Spring Security 에서 제공하는 Authentication 인터페이스의 구현체 중 하나
  - username 과 password 로 인증할 때 사용, 인증 후 사용자 정보와 권한을 담는 데 사용
  - User 의 IP Address 나 Session ID 등을 설정 가능

## SecurityConfig

---

- SecurityConfig 의 목적:
  - Application 의 보안 설정을 정의하여 인증 및 권한 부여 매커니즘을 구성
  - JWT 를 사용한 인증을 Spring Security 와 통합
- 핵심 기능:
  - CSRF 보호 비활성화 -> 상태가 없는 인증을 위해 필요 없는 기능을 비활성화
  - 접근 제어 규칙 설정 -> 특정 경로에 대한 접근 권한을 정의
  - 세션 관리 설정 -> 서버 측 세션을 사용하지 않도록 설정
  - 커스텀 필터 추가 -> JWT 인증을 처리하는 필터를 추가하여 요청 처리 과정에 포함
  - 비밀번호 인코더 및 인증 관리자 제공 -> 보안 관련 빈을 생성하여 Application 에서 사용