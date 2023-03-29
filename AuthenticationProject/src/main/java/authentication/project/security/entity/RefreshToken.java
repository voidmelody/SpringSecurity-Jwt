package authentication.project.security.entity;

import authentication.project.member.entity.Member;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RefreshToken {

    @Id @GeneratedValue
    private Long id;

    @Column
    private String token;

    @Column
    private Long expiration;

    @OneToOne
    @JoinColumn(name="USER_ID")
    private Member member;
}
