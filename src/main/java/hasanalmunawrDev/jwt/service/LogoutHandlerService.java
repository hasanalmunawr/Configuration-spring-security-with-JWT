package hasanalmunawrDev.jwt.service;

import hasanalmunawrDev.jwt.entity.RefreshTokenEntity;
import hasanalmunawrDev.jwt.entity.TokenType;
import hasanalmunawrDev.jwt.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@RequiredArgsConstructor
@Service
public class LogoutHandlerService implements LogoutHandler {

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!authHeader.startsWith(TokenType.Bearer.name())) {
            return;
        }

        final String refreshToken = authHeader.substring(7);
        log.info("[LogoutHandlerService:logout] access token : {}", refreshToken);

        var storedRefreshToken = refreshTokenRepository.findByRefreshToken(refreshToken)  // WHY IS IT BE NULL
//                .map(token->{
//                    token.setRevoked(true);
//                    refreshTokenRepository.save(token);
//                    return token;
//                })
                .orElse(null);
        storedRefreshToken.setRevoked(true);
        refreshTokenRepository.save(storedRefreshToken);
        log.info("[LogoutHandlerService:logout] access has by : {}", storedRefreshToken.getUserEntity().getUsername());



    }
}
