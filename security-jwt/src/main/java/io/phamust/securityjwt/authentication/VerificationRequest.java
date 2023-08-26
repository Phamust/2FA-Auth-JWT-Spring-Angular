package io.phamust.securityjwt.authentication;

import lombok.Builder;
import lombok.Data;

/**
 * @author Phamust.io
 */
@Data
@Builder
public class VerificationRequest {

    private String email;
    private String code;
}
