package authentication.project.security;

import authentication.project.member.dto.MemberLogin;
import authentication.project.member.dto.SignResponseDto;
import authentication.project.member.entity.Member;
import authentication.project.security.config.SecurityConfig;
import authentication.project.security.dto.TokenDto;
import authentication.project.security.entity.RefreshToken;
import authentication.project.security.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    private final Long accessToken_expired = SecurityConfig.accessToken_expired;
    private final Long refreshToken_expired = SecurityConfig.refreshToken_expired;


    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, AuthenticationManager authenticationManager, RefreshTokenRepository refreshTokenRepository){
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.refreshTokenRepository = refreshTokenRepository;
        setFilterProcessesUrl("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try{
            ObjectMapper objectMapper = new ObjectMapper();
            MemberLogin member = objectMapper.readValue(request.getInputStream(), MemberLogin.class);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(member.getUsername(), member.getPassword());

            return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        Member member = (Member) authResult.getPrincipal();

        SignResponseDto signResponseDto = SignResponseDto.builder()
                .id(member.getMemberId())
                .username(member.getUsername())
                .name(member.getName())
                .contact(member.getContact())
                .email(member.getEmail())
                .role(member.getRole().toString())
                .token(TokenDto.builder()
                        .access_token(jwtTokenProvider.createToken(member.getUsername(), member.getRole().toString(), accessToken_expired))
                        .refresh_token(jwtTokenProvider.createToken(member.getUsername(), member.getRole().toString(), refreshToken_expired))
                        .build())
                .build();

        log.info("jwt AccessToken = {}", signResponseDto.getToken().getAccess_token());

        String jsonStr = new ObjectMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(signResponseDto);

        response.getWriter().write(jsonStr);

        // 저장
        RefreshToken refreshToken = refreshTokenRepository.save(
                RefreshToken.builder()
                        .id(member.getMemberId())
                        .token(signResponseDto.getToken().getRefresh_token())
                        .expiration(refreshToken_expired)
                        .member(member)
                        .build()
        );
    }
}
