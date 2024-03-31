package hasanalmunawrDev.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenGenerator {

    private final JwtEncoder jwtEncoder;

    public String generateRefreshToken(Authentication authentication) {
        log.info("[JwtTokenGenerator:generateRefreshToken] Token Creation started fro : {}", authentication.getName());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("hasan")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", "REFRESH_TOKEN")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateAccessToken(Authentication authentication) {
        log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for : {} ", authentication.getName());

        String role = getRolesOfUser(authentication);

        String permissions = getPermissionsFromRoles(role);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("hasan")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(1, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", permissions)
                .build();

        return jwtEncoder
                .encode(JwtEncoderParameters.from(claims))
                .getTokenValue();
    }

    private String getPermissionsFromRoles(String role) {
        Set<String> permissions = new HashSet<>();

        if (role.contains("ROLE_ADMIN")) {
            permissions.addAll(List.of("READ, WRITE", "DELETE"));
        }
        if (role.contains("ROLE_MANAGER")) {
            permissions.addAll(List.of("READ", "WRITE"));
        }
        if (role.contains("ROLE_USER")) {
            permissions.add("READ");
        }
        return String.join(" ", permissions);
    }

    private String getRolesOfUser(Authentication authentication) {
        return authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }
}
