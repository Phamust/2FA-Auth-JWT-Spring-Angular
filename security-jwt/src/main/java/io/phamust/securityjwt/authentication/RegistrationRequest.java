package io.phamust.securityjwt.authentication;

import io.phamust.securityjwt.appuser.AppUserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationRequest {
    private String name;
    private String lastName;
    private String email;
    private String password;
    private AppUserRole role;
    private boolean mfaEnabled;

}
