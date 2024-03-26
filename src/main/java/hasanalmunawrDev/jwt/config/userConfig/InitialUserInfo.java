package hasanalmunawrDev.jwt.config.userConfig;

import hasanalmunawrDev.jwt.entity.Role;
import hasanalmunawrDev.jwt.entity.UserEntity;
import hasanalmunawrDev.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class InitialUserInfo implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        UserEntity manager = new UserEntity();
        manager.setUsername("Manager");
        manager.setPassword(passwordEncoder.encode("password"));
        manager.setRoles(Role.MANAGER.getName());
        manager.setEmailId("manager@manager.com");

        UserEntity admin = new UserEntity();
        admin.setUsername("Admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setRoles(Role.ADMIN.getName());
        admin.setEmailId("admin@admin.com");

        UserEntity user = new UserEntity();
        user.setUsername("User");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRoles(Role.USER.getName());
        user.setEmailId("user@user.com");

        userRepository.saveAll(List.of(admin, manager, user));

    }
}
