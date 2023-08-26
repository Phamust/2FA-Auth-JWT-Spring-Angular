package io.phamust.securityjwt.authentication;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(NON_EMPTY)
public class AuthenticationResponse {

    private String accessToken;
    private String refreshToken;
    private Boolean mfaEnabled;
    private String secretImageUri;
}