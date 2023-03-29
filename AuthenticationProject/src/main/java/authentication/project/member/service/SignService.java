package authentication.project.member.service;


import authentication.project.member.Authority;
import authentication.project.member.dto.SignRequestDto;
import authentication.project.member.dto.SignResponseDto;
import authentication.project.member.entity.Member;
import authentication.project.member.repository.MemberRepository;
import authentication.project.security.*;
import authentication.project.security.config.SecurityConfig;
import authentication.project.security.dto.TokenDto;
import authentication.project.security.entity.RefreshToken;
import authentication.project.security.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class SignService {
    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private long accessToken_expired = SecurityConfig.accessToken_expired;

    public boolean registerByRole(SignRequestDto request, String role) throws Exception{
        Member member = Member.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .contact(request.getContact())
                .email(request.getEmail())
                .build();
        if(role.equals(Authority.valueOf("ROLE_ADMIN").getValue())){
            member.setRole(Authority.valueOf("ROLE_ADMIN"));
        }else{
            member.setRole(Authority.valueOf("ROLE_USER"));
        }
        memberRepository.save(member);
        return true;
    }

    public SignResponseDto getMember(String username) throws Exception{
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new Exception("계정을 찾을 수 없습니다."));
        return new SignResponseDto(member);
//        return SignResponseDto.builder()
//                .id(member.getMemberId())
//                .username(member.getUsername())
//                .name(member.getName())
//                .contact(member.getContact())
//                .email(member.getEmail())
//                .role(member.getRole().toString())
//                .token(TokenDto.builder()
//                        .access_token(jwtTokenProvider.createToken(member.getUsername(), member.getRole().toString(), accessToken_expired)) // 수정필요
//                        .refresh_token(refreshTokenRepository.findByMember(member).orElseThrow().getToken())
//                        .build())
//                .build();
    }

    public RefreshToken validRefreshToken(Member member, String token) throws Exception{
        RefreshToken refreshToken = refreshTokenRepository.findByMember(member).orElseThrow(NullPointerException::new);
        if(refreshToken == null)
            throw new Exception();
        if(refreshToken.getToken() == null){
            return null;
        }else{
            // 토큰이 같은지 비교
            if(!refreshToken.getToken().equals(token)){
                return null;
            }
            return refreshToken;
        }
    }

    public TokenDto refreshAccessToken(TokenDto tokenDto) throws Exception{
        String username = jwtTokenProvider.getUserName(tokenDto.getAccess_token());
        Member member = memberRepository.findByUsername(username).
                orElseThrow(()-> new BadCredentialsException("잘못된 계정 정보입니다."));

        RefreshToken refreshToken = validRefreshToken(member, tokenDto.getRefresh_token());

        if(refreshToken != null){
            return TokenDto.builder()
                    .access_token(jwtTokenProvider.createToken(username, member.getRole().toString(), accessToken_expired))
                    .refresh_token(refreshToken.getToken())
                    .build();
        }else{
            throw new Exception("로그인을 해주세요.");
        }
    }
}
