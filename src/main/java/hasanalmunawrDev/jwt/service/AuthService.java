package hasanalmunawrDev.jwt.service;

import hasanalmunawrDev.jwt.dto.AuthResponseDto;
import hasanalmunawrDev.jwt.entity.TokenType;
import hasanalmunawrDev.jwt.config.jwt.JwtTokenGenerator;
import hasanalmunawrDev.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;

    private final JwtTokenGenerator jwtTokenGenerator;

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication) {
        log.info("THE NAME OF USERNAME IS {} ",authentication.getName());
        try {
            var userEntity = userRepository.findByEmailId(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthService:userSignInAuth] User : {} Not Found ", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND");
                    });

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            log.info("[AuthService:userSignInAuth] Access token for user {} has generated", userEntity.getUsername());

            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .username(userEntity.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();
        } catch (Exception e) {
            log.error("[AuthService:usersignInAuth] Exception while authenticating the use due to : {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }
}
