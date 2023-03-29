package authentication.project.member;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Authority {
    ROLE_USER("USER"),
    ROLE_ADMIN("ADMIN");

    private String value;
}
