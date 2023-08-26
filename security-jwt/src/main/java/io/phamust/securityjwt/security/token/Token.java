package io.phamust.securityjwt.security.token;
import io.phamust.securityjwt.appuser.AppUser;
import jakarta.persistence.*;
import lombok.*;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token  {

    @Id
    @SequenceGenerator(
            name = "token_sequence"
            ,sequenceName = "token_sequence"
            ,allocationSize = 1)
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE
            ,generator = "token_sequence")
    private Long id;
    @Column(unique = true)
    public String token;

    @Enumerated(EnumType.STRING)
    public TokenType tokenType = TokenType.BEARER;

    public boolean revoked;

    public boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public AppUser user;
}