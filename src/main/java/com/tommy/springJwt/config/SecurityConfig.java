package com.tommy.springJwt.config;

import com.tommy.springJwt.filter.JwtAuthenticationFilter;
import com.tommy.springJwt.service.UserDetailsServiceImp;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Component  // 해당 class 가 Spring 의 컴포넌트 스캔에 의해 자동으로 빈으로 등록
@EnableWebSecurity  // Spring Security 의 웹 보안 지원을 활성화 -> Spring MVC 통합 제공
public class SecurityConfig {

    // CustomUserDetails implement 와 JwtFilter
    private final UserDetailsServiceImp userDetailsServiceImp;      // User 정보 -> 데이터베이스 로드 위해 필요
    private final JwtAuthenticationFilter jwtAuthenticationFilter;  // JWT 인증 처리 커스텀 필터

    public SecurityConfig(UserDetailsServiceImp userDetailsServiceImp, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userDetailsServiceImp = userDetailsServiceImp;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean   // 해당 메서드가 Spring Container 에 의해 관리되는 Bean 을 생성
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {    // 보안 FilterChain 을 구성하고 반환

        return http
                /* ----- CSRF 보호 비활성화 -----
                * CSRF(Cross-Site Request Forgery) 보호 비활성화
                * 이유 -> JWT 를 사용하는 RESTful API 에서는 상태가 없는(stateless) 인증을 사용
                * */
                .csrf(AbstractHttpConfigurer::disable)
                // 요청에 대한 접근 제어 설정
                .authorizeHttpRequests(
                        req->req.requestMatchers("/login/**", "/register/**").permitAll()    // 인증 접근 허용
                                .requestMatchers("/admin_only/**").hasAnyAuthority("ADMIN") // ADMIN 권한 User만 접근 허용
                                .anyRequest().authenticated()    // 위에서 명시한 경로를 제외한 모든 요청에 대해 인증 요구
                ).userDetailsService(userDetailsServiceImp) // User 세부 정보 서비스 설정
                /* ----- 세션 관리 설정 -----
                * 세션 생성 정책 -> SessionCreationPolicy.STATELESS 로 설정하여 서버가 세션을 생성하거나 유지하지 않도록 설정
                * 이유 -> JWT 를 사용한 인증에서는 클라이언트 측에서 토큰을 관리, 서버 측 세션 관리가 필요 없음
                * */
                .sessionManagement(session->session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                /* ----- 커스텀 JWT 인증 추가 -----
                * jwtAuthenticationFilter 를 UsernamePasswordAuthenticationFilter 앞에 추가
                * 이유 -> JWT 인증이 username/password 인증보다 먼저 이루어져야 하므로 필터 체인에서 앞쪽에 패치
                * */
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();   // 설정한 내용의 보안 필터 체인을 생성하고 반환
    }

    /*
    * 비밀번호를 안전하게 저장하기 위해 BCrypt Hash 함수를 사용하는 PasswordEncoder 빈을 생성
    * 사용자 비밀번호를 데이터베이스에 저장할 때 해시화하여 저장
    * 인증 시 입력된 비밀번호를 해시화하여 저장된 해시 값과 비교
    * */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    * AuthenticationManager 를 Bean 으로 노출하여 Application 의 다른 부분에서 인증을 수행할 수 있도록 함
    * AuthenticationManager -> Spring Security 의 핵심 인터페이스, 사용자 인증 담당
    * 로그인 로직에서 사용자 인증을 직접 수행할 때 필요
    * */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


}
