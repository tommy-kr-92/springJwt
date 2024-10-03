package com.tommy.springJwt.service;

import com.tommy.springJwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "778f2b4bee5937982784f5e05364726fa662cf3c7dcdfa0a3db92aaed2c62759";

    /*
    * 토큰에서 사용자 이름(subject)을 추출
    * extractClaim() 호출하여 subject 클레임을 가져옴
    * */
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    /*
    * 주어진 토큰이 유효한지 검사
    * 토큰에서 추출한 사용자 이름이 제공된 UserDetails 의 사용자 이름과 일치하는지 확인
    * 토큰이 만료되지 않았는지 확인
    * 인증 과정에서 토큰의 신뢰성을 검증하기 위해 사용
    * */
    public boolean isValid(String token, UserDetails user){
        String username = extractUsername(token);
        return username.equals(user.getUsername()) && !isTokenExpired(token);
    }

    /*
    * 토큰이 만료되었는지 확인
    * 토큰의 만료 시간(expiration 클레임)이 현재 시간보다 이전인지 비교
    * */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /*
    * 토큰에서 만료 시간 정보를 추출
    * extractClaim 메서드를 사용하여 expiration 클레임을 가져옴
    * */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /*
    * 토큰에서 특정 클레임을 추출하는 제네릭 메서드
    * extractAllClaim() 을 호출하여 모든 클레임을 가져옴
    * 전달된 함수형 인터페이스 resolver 를 사용하여 원하는 클레임을 추출
    * 이 메서드를 통해 다양한 종류의 클레임을 쉽게 추출
    * */
    public <T> T extractClaim(String token, Function<Claims, T> resolver){
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    /*
    * 토큰에서 모든 클레임 정보를 추출
    * JWT parse() 를 생성하고 서명키 설정
    * 토큰을 파싱하여 서명을 검증하고 클레임(payload)을 반환
    * ========== 주의사항 ==========
    * 사용하는 JWT 라이브러리의 버전에 따라 메서드 체인이 달라질 수 있음
    * 해당 버전에 맞는 API 를 사용해야 함
    * */
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    /*
    * 주어진 사용자 정보를 기반으로 JWT 토큰을 생성
    * subject: 토큰의 주체 -> User 의 username
    * issuedAt: 토큰 발행 시간
    * expiration: 토큰 만료 시간
    * signWith: 토큰을 서명하기 위한 서명 키 설정
    * Jwts.Builder() 를 사용하여 토큰 구성 -> Builder Pattern
    * 필요한 클레임과 서병 키를 설정 후 compact() 를 호출하여 직렬화된 JWT 문자열 생성
    * */
    public String generateToken(User user){
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .claim("roles", user.getRole())     // 특정 필드를 권한 부여에 활용 가능
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))   // 만료시간 -> 24h
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)     // 서명 알고리즘 -> HS256으로 지정
                .compact();
        return token;
    }

    /*
    * 서명 및 검증에 사용할 SecretKey 객체 생성
    * SECRET_KEY 를 Base64 URL 형식으로 디코딩하여 바이트 배열로 변환
    * Keys.hmacShaKeyFor() 를 상요하여 HMAC-SHA 알고리즘에 적합한 SecretKey 를 생성
    * */
    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
