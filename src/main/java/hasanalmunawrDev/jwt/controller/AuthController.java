package hasanalmunawrDev.jwt.controller;

import hasanalmunawrDev.jwt.dto.UserRegrestationDto;
import hasanalmunawrDev.jwt.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(Authentication authentication,
                                              HttpServletResponse response) {
        return ResponseEntity
                .ok(authService.getJwtTokensAfterAuthentication(authentication, response));
    }

    @PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN')")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String auhtorizationHeader) {
        return ResponseEntity
                .ok(authService.getAccessTokenUsingRefreshToken(auhtorizationHeader));
    }

    @PostMapping(value = "/sign-up", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegrestationDto regrestationDto,
                                          BindingResult bindingResult,
                                          HttpServletResponse response) {
        log.info("[AuthController:registerUser] SignUp Process Started for user {}", regrestationDto.username());

        if (bindingResult.hasErrors()) {
            List<String> errorsMesage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            log.error("[AuthController:registerUser] Errors in user {}", regrestationDto.username());
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST).body(errorsMesage);
        }
        return ResponseEntity
                .ok(authService.registerUser(regrestationDto, response));
    }


}
