package io.phamust.securityjwt.appuser;
import io.phamust.securityjwt.security.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "app_user")
public class AppUser implements UserDetails {
    @Id
    @SequenceGenerator(
            name = "user_sequence"
            ,sequenceName = "user_sequence"
            ,allocationSize = 1)
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE
            ,generator = "user_sequence")
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private AppUserRole appUserRole;
    @OneToMany(mappedBy = "user")
    private List<Token> tokens;

    private boolean mfaEnabled;
    private String secret;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return appUserRole.getAuthorities();
    }

    @Override
    public String getUsername() {
        return email;
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
