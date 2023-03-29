package authentication.project.security.config;

import authentication.project.security.JwtAuthenticationFilter;
import authentication.project.security.JwtAuthorizationFilter;
import authentication.project.security.JwtTokenProvider;
import authentication.project.security.repository.RefreshTokenRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import java.io.IOException;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    public static final long accessToken_expired = 1000L * 60 * 60; // 1시간
    public static final long refreshToken_expired = 2000L * 60 * 60; // 2시간
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception
    {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                // 문자열을 Base64로 인코딩 전달
                .httpBasic().disable()
                // 쿠키 기반이 아닌 JWT 기반이므로 사용 X
                .csrf().disable()
                .cors()
                .and()
                //Spring Security 세션 정책 : 세션을 생성 및 사용하지 않음
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 조건 별로 요청 허용 / 제한 설정
                .authorizeHttpRequests()
                // 회원 가입과 로그인은 모두 승인
                    .requestMatchers("/", "/register/**", "/login/**", "/refresh/**").permitAll()
                // /admin 시작 요청은 ADMIN 권한이 있는 유저에게만 허용
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                // /user 시작 요청은 USER 권한이 있는 유저에게만 허용
                    .requestMatchers("/user/**").hasRole("USER")
                    .anyRequest().denyAll()
                .and()
                // login 주소가 호출되면 인증 및 토큰 발행 필터 추가
                .addFilter(new JwtAuthenticationFilter(jwtTokenProvider, authenticationManager(), refreshTokenRepository))
                // JWT 토큰검사
                .addFilterBefore(new JwtAuthorizationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                // 에러 헨들링
                .exceptionHandling()
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        // 권한 문제 발생 시 해당 부분 호출
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403
                        response.setCharacterEncoding("utf-8");
                        response.setContentType("text/html; charset=UTF-8");
                        response.getWriter().write("권한이 없는 사용자입니다.");
                    }
                })
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        // 인증 문제 발생 시 해당 부분 호출
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
                        response.setCharacterEncoding("utf-8");
                        response.setContentType("text/html; charset=UTF-8");
                        response.getWriter().write("인증되지 않은 사용자입니다.");
                    }
                });
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        // createDelegatingPasswordEncoder()를 통해 비밀번호 앞에 Encoding 방식이 붙은 채로 저장된다.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
