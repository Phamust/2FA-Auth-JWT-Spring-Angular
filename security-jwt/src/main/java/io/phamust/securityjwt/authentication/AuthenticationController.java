package io.phamust.securityjwt.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping(path = "/register",consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<?> registerUser(@RequestBody RegistrationRequest request){
       var response = authenticationService.register(request);
       if (request.isMfaEnabled()){
           return ResponseEntity.ok(response);
       }
        return ResponseEntity.accepted().build() ;
    }

    @PostMapping(path = "/authenticate",consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthenticationResponse> authenticateUser(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request, response);
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@RequestBody VerificationRequest verificationRequest) {
        return ResponseEntity.ok(authenticationService.verifyCode(verificationRequest));
    }

}
