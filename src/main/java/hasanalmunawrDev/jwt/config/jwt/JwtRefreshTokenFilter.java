package hasanalmunawrDev.jwt.config.jwt;

import hasanalmunawrDev.jwt.config.RSAKeyRecord;
import hasanalmunawrDev.jwt.repository.RefreshTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtRefreshTokenFilter extends OncePerRequestFilter
{

    private final RSAKeyRecord rsaKeyRecord;

    private final JwtTokenUtils jwtTokenUtils;

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("[JwtRefreshTokenFilter:doFilterInternal] :: Started");

            log.info("[JwtRefreshTokenFilter:doFilterInternal] Filtering the Http Request: {}", request);

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            JwtDecoder jwtDecoder = NimbusJwtDecoder
                    .withPublicKey(rsaKeyRecord.rsaPublicKey()).build();

            if (!authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }

            final String token = authHeader.substring(7);
            final Jwt jwtRefreshToken = jwtDecoder.decode(token);

            final String username = jwtTokenUtils.getUsername(jwtRefreshToken);

            if (!username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                // check if refreshToken isPresent in databse and valid
                var isRefreshTokenValisInDatabase = refreshTokenRepository
                        .findByRefreshToken(jwtRefreshToken.getTokenValue())
                        .map(refreshTokenEntity -> !refreshTokenEntity.isRevoked())
                        .orElse(false);

                UserDetails userDetails = jwtTokenUtils.userDetailsByName(username); // email / name ?
                if (jwtTokenUtils.isTokenValid(jwtRefreshToken, userDetails)) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtRefreshTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        } catch (JwtValidationException jwtEx) {
            log.error("[JwtRefreshTokenFiler:doFilterInternal] Exception due to : {}", jwtEx.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtEx.getMessage());
        }
    }
}
