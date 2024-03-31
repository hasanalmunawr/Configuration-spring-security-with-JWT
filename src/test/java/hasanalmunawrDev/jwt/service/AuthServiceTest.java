package hasanalmunawrDev.jwt.service;

import hasanalmunawrDev.jwt.config.jwt.JwtTokenGenerator;
import hasanalmunawrDev.jwt.dto.AuthResponseDto;
import hasanalmunawrDev.jwt.entity.TokenType;
import hasanalmunawrDev.jwt.entity.UserEntity;
import hasanalmunawrDev.jwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtTokenGenerator jwtTokenGenerator;

    @Test
    public void testGetJwtTokensAfterAuthentication_Success() throws Exception {
        // Mock user entity
        String username = "testuser";
        String email = "testuser@example.com";
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setEmailId(email);
        userEntity.setPassword("password");

        // Mock authentication object
        Authentication authentication = Mockito.mock(Authentication.class);
        Mockito.when(authentication.getName()).thenReturn(email);

        // Mock JWT token generation
        String accessToken = "eyJhbGciNiIsInR5..."; // Sample access token

        // Mock repository behavior
        Mockito.when(userRepository.findByEmailId(email)).thenReturn(Optional.of(userEntity));
        Mockito.when(jwtTokenGenerator.generateAccessToken(authentication)).thenReturn(accessToken);

        // Call the method under test
//        AuthResponseDto responseDto = authService.getJwtTokensAfterAuthentication(authentication, response);

        // Assertions
//        assertNotNull(responseDto);
//        log.info(responseDto.getAccessToken());
//        assertEquals(accessToken, responseDto.getAccessToken());
//        assertEquals(15 * 60, responseDto.getAccessTokenExpiry());
//        assertEquals(username, responseDto.getUsername());
//        assertEquals(TokenType.Bearer, responseDto.getTokenType());
    }

    @Test()
    public void testGetJwtTokensAfterAuthentication_UserNotFound() throws Exception {
        // Mock authentication object
        String email = "notfound@example.com";
        Authentication authentication = Mockito.mock(Authentication.class);
        Mockito.when(authentication.getName()).thenReturn(email);

        // Mock repository behavior (user not found)
        Mockito.when(userRepository.findByEmailId(email)).thenReturn(Optional.empty());

        // Call the method under test (expect exception)
//        authService.getJwtTokensAfterAuthentication(authentication, response);
    }

    @Test()
    public void testGetJwtTokensAfterAuthentication_Exception() throws Exception {
        // Mock authentication object
        String email = "testuser@example.com";
        Authentication authentication = Mockito.mock(Authentication.class);
        Mockito.when(authentication.getName()).thenReturn(email);

        // Mock repository behavior
        Mockito.when(userRepository.findByEmailId(email)).thenReturn(Optional.of(new UserEntity()));

        // Mock JWT token generation (exception)
        Mockito.when(jwtTokenGenerator.generateAccessToken(authentication)).thenThrow(new RuntimeException("Token generation failed"));

        // Call the method under test (expect exception)
//        authService.getJwtTokensAfterAuthentication(authentication, response);
    }
}
