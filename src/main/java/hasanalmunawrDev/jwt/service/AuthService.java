package hasanalmunawrDev.jwt.service;

import hasanalmunawrDev.jwt.config.userConfig.UserInfoMapper;
import hasanalmunawrDev.jwt.dto.AuthResponseDto;
import hasanalmunawrDev.jwt.dto.UserRegrestationDto;
import hasanalmunawrDev.jwt.entity.RefreshTokenEntity;
import hasanalmunawrDev.jwt.entity.TokenType;
import hasanalmunawrDev.jwt.config.jwt.JwtTokenGenerator;
import hasanalmunawrDev.jwt.entity.UserEntity;
import hasanalmunawrDev.jwt.repository.RefreshTokenRepository;
import hasanalmunawrDev.jwt.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final JwtTokenGenerator jwtTokenGenerator;

    private final UserInfoMapper userInfoMapper;

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication,
                                                           HttpServletResponse response) {
        log.info("THE NAME OF USERNAME IS {} ",authentication.getName());
        try {

            var userEntity = userRepository
                    .findByUsername(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthService:userSignInAuth] User : {} Not Found ", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND");
                    });

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            createRefreshTokenCookie(response, refreshToken);
            saveUserRefreshToken(userEntity, refreshToken);
            log.info("[AuthService:userSignInAuth] Access token for user {} has generated", userEntity.getUsername());

            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(1 * 1)
                    .username(userEntity.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();
        } catch (Exception e) {
            log.error("[AuthService:usersignInAuth] Exception while authenticating the use due to : {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }

    public Object getAccessTokenUsingRefreshToken(String authorizationHeader)  {
        if (!authorizationHeader.startsWith(TokenType.Bearer.name())) {
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type");
        }

        final String refreshToken = authorizationHeader.substring(7);

        var refreshTokenEntity = refreshTokenRepository
                .findByRefreshToken(refreshToken)
                .filter(tokens -> !tokens.isRevoked())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh Token REVOKED"));

        UserEntity userEntity = refreshTokenEntity.getUserEntity();

        Authentication authenticationObject = createAuthenticationObject(userEntity);

        String accessToken = jwtTokenGenerator.generateAccessToken(authenticationObject);

        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60) // In seconds
                .username(userEntity.getUsername())
                .tokenType(TokenType.Bearer)
                .build();
    }

    public AuthResponseDto registerUser(UserRegrestationDto regrestationDto, HttpServletResponse response) {
        try {
            log.info("[AuthService:registerUser] User Registration started with :: {}", regrestationDto.username());

            Optional<UserEntity> existUser = userRepository
                    .findByEmailId(regrestationDto.email());

            if (existUser.isPresent()) {
                throw new Exception("User Already Exist");
            }

            UserEntity user = userInfoMapper.convertToEntity(regrestationDto);
            Authentication authenticationObject = createAuthenticationObject(user);

            // Generate a JWT token
            String accessToken = jwtTokenGenerator.generateAccessToken(authenticationObject);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authenticationObject);

            UserEntity saveUser = userRepository.save(user);
            saveUserRefreshToken(user, refreshToken);

            createRefreshTokenCookie(response, refreshToken);

            log.info("[AuthService:registerUser] User : {} Successfully registered", saveUser);
            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .username(saveUser.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();

        } catch (Exception e) {
            log.error("[AuthService:registerUser]Exception while registering the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }


    private static Authentication createAuthenticationObject(UserEntity userEntity) {
        // Extract user details from userdetailEntity
        String username = userEntity.getEmailId();
        String password = userEntity.getPassword();
        String roles = userEntity.getRoles();

        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }
    private void saveUserRefreshToken(UserEntity userEntity, String refeshToken) {
        var refreshTokenEntity = RefreshTokenEntity.builder()
                .userEntity(userEntity)
                .refreshToken(refeshToken)
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);
    }

    private Cookie createRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60); // In Seconds
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }
}
