package hasanalmunawrDev.jwt.config.userConfig;

import hasanalmunawrDev.jwt.dto.UserRegrestationDto;
import hasanalmunawrDev.jwt.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class UserInfoMapper {

    private final PasswordEncoder passwordEncoder;

    public UserEntity convertToEntity(UserRegrestationDto userRegrestationDto) {
        return UserEntity.builder()
                .username(userRegrestationDto.username())
                .emailId(userRegrestationDto.email())
                .password(userRegrestationDto.password())
                .mobileNumber(userRegrestationDto.mobileNumber())
                .roles(userRegrestationDto.role())
                .build();
    }
}
