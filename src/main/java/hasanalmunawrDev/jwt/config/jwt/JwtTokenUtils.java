package hasanalmunawrDev.jwt.config.jwt;

import hasanalmunawrDev.jwt.config.UserConfig;
import hasanalmunawrDev.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenUtils {

    private final UserRepository userRepository;

    public String getUsername(Jwt jwtToken) {
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails) {
        final String username = getUsername(jwtToken);
        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
        boolean isTokenUserSameAsDatabase = username.equals(userDetails.getUsername());
        return  !isTokenExpired && isTokenUserSameAsDatabase;
    }

    private boolean getIfTokenIsExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }


    public UserDetails userDetailsByName(String username) {
        if (username.endsWith(".com")) {
            return userRepository
                    .findByEmailId(username)
                    .map(UserConfig::new)
                    .orElseThrow(() -> new UsernameNotFoundException("Email with "+username+" Can not Found"));
        }
        log.info("[JwtTokenUtils:userDetailsByName] The name is {}", username);
        /*kalo generate token ini pake username, tapi kalo refresh token ini pake email, Lets say ini konsisten pake email*/
        return userRepository
                .findByUsername(username)
                .map(UserConfig::new)
                .orElseThrow(() -> new UsernameNotFoundException("User with "+username+" Can not Found"));
    }



}
