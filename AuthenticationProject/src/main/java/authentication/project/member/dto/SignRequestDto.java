package authentication.project.member.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignRequestDto {
    private Long id;

    private String username;

    private String password;

    private String name;

    private String contact;

    private String email;
}
