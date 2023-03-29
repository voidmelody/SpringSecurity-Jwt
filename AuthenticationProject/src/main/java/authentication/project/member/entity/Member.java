package authentication.project.member.entity;


import authentication.project.member.Authority;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Member implements UserDetails {

    @Id @GeneratedValue
    private Long memberId;

    private String username; // 로그인 id

    private String password;

    private String name;

    private String contact;

    private String email;

    @Enumerated(EnumType.STRING)
    private Authority role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<String> lists = Stream.of(Authority.values())
                .map(Enum::name)
                .collect(Collectors.toList());

        return lists.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
