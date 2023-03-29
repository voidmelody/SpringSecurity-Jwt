package authentication.project.security;

import authentication.project.member.entity.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final CustomUserDetailService userDetailService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        // AuthenticationFilter에서 생성된 토큰으로부터 아이디와 비밀번호 조회
        String username = token.getName();
        String password = (String)token.getCredentials();
        //UserDetailsService를 통해 DB에서 아이디로 사용자 조회
        Member member = (Member)userDetailService.loadUserByUsername(username);
        if(!passwordEncoder.matches(password, member.getPassword())){
            throw new BadCredentialsException(member.getUsername() + "Invalid Password!!");
        }
        return new UsernamePasswordAuthenticationToken(member, password, member.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
       return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
