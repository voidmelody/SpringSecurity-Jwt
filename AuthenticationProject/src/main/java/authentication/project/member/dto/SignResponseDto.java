package authentication.project.member.dto;

import authentication.project.member.entity.Member;
import authentication.project.security.dto.TokenDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignResponseDto {
    private Long id;

    private String username;

    private String name;

    private String contact;

    private String email;

    private String role;

    private TokenDto token;

    public SignResponseDto(Member member){
        this.id = member.getMemberId();
        this.username = member.getUsername();
        this.name = member.getName();
        this.contact = member.getContact();
        this.email = member.getEmail();
        this.role = member.getRole().toString();
    }
}
