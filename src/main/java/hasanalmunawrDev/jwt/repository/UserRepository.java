package hasanalmunawrDev.jwt.repository;

import hasanalmunawrDev.jwt.entity.UserEntity;
import org.apache.catalina.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {

    Optional<UserEntity> findByEmailId(String emailId);

    Optional<UserEntity> findByUsername(String username);
}
