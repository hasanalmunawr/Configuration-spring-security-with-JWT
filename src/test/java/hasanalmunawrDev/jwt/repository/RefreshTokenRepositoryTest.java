package hasanalmunawrDev.jwt.repository;

import hasanalmunawrDev.jwt.entity.RefreshTokenEntity;
import hasanalmunawrDev.jwt.entity.UserEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        UserEntity user = new UserEntity();
        user.setUsername("username");
        user.setEmailId("username@user.com");
        user.setPassword("rahasia");
        user.setRoles("ROLE_USER");
        userRepository.save(user);


        RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
        refreshTokenEntity.setRevoked(false);
        refreshTokenEntity.setRefreshToken("hasanalmunawar");
        refreshTokenEntity.setUserEntity(user);
        refreshTokenRepository.save(refreshTokenEntity);
    }

    @Test
    void findByRefreshToken() {
        RefreshTokenEntity refreshTokenEntity = refreshTokenRepository.findByRefreshToken("hasanalmunawar").orElse(null);
        assertNotNull(refreshTokenEntity);

    }

    @Test
    void findAllRefreshTokenByUserEmailId() {
    }
}