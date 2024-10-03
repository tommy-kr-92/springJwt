package com.tommy.springJwt.filter;

import com.tommy.springJwt.service.JwtService;
import com.tommy.springJwt.service.UserDetailsServiceImp;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImp userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsServiceImp userDetails, UserDetailsServiceImp userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // ========================================================
        //          Authorization Header 에서 token 추출
        // ========================================================
        String authHeader = request.getHeader("Authorization");     // Authorization Header

        // Authorization Header 가 비어 있거나 Bearer 로 시작하지 않으면
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);    // 인증 정보가 없다 간주 -> 필터 체인의 다음 필터 호출
            return;
        }

        // ========================================================
        //                  Token 과 Username 추출
        // ========================================================
        String token = authHeader.substring(7);     // substring(7) 을 사용하여 'Bearer  ' 제거
        String username = jwtService.extractUsername(token);    // token 의 subject 클레임에서 사용자명 추출

        // username 이 null 이 아니고 SecurityContext 에 인증 정보가 없는 경우에만 인증 진행 -> '중복 인증 방지'
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){

            // Database 에서 User 정보 가져옴
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            /* ----- 토큰 유요형 검증 -----
            * 토큰 서명 유효?
            * 토큰 만료?
            * 토큰 username 과 userDetails 의 username 일치?
            * */
            if(jwtService.isValid(token, userDetails)){

                // ========================================================
                //            인증 객체 생성 및 SecurityContext 설정
                // ========================================================
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(        // UsernamePasswordAuthenticationToken 객체 생성
                        userDetails,    // principal -> 사용자 정보(userDetails)
                        null,           // credentials -> 비밀번호(null 로 설정, 이미 인증됨)
                        userDetails.getAuthorities()    // authorities -> 사용자 권한 목록
                );

                authToken.setDetails(       // 인증 객체에 request 의 추가 정보 설정
                        // WebAuthenticationDetailsSource 객체를 사용 -> 현재 요청의 상세 정보 빌드
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // SecurityContextHolder.getContext().setAuthentication() 을 호출
                // 현재 스레드의 보안 컨텍스트에 인증 객체를 설정
                SecurityContextHolder.getContext().setAuthentication(authToken);    // 이후 보안 관련 작업에서 authToken 사용
            }
        }

        // FilterChain 게속 진행
        // 필터 체인의 다음 필터를 호출하여 요청 처리를 계속
        // 모든 인증 작업이 완료된 후에도 doFilter 를 호출해야 함
        filterChain.doFilter(request, response);
    }
}
