package hasanalmunawrDev.jwt.service;

import hasanalmunawrDev.jwt.entity.RefreshTokenEntity;
import hasanalmunawrDev.jwt.entity.TokenType;
import hasanalmunawrDev.jwt.exception.TokenNotFoundException;
import hasanalmunawrDev.jwt.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@RequiredArgsConstructor
@Service
public class LogoutHandlerService implements LogoutHandler {

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        try {
            if (!authHeader.startsWith(TokenType.Bearer.name())) {
                return;
            }

            final String refreshToken = authHeader.substring(7);

            var storedToken = refreshTokenRepository.findByRefreshToken(refreshToken) // on this always be NULL
                    .orElseThrow(() -> new TokenNotFoundException("Token not found"));
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            refreshTokenRepository.save(storedToken);

            SecurityContextHolder.clearContext();

            log.info("[LogoutHandlerService:logout] Refresh Token  Revoked : {}", refreshToken); // at this the token is exist

        } catch (TokenNotFoundException e) {
            log.warn("[LogoutHandlerService:logout] Token not found: ", e);
        } catch (Exception e) {
            log.error("[LogoutHandlerService:logout] Error revoking token: {}", e.getMessage());

        }
    }
}
