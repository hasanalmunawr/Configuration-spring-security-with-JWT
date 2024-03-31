package hasanalmunawrDev.jwt.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name = "users_entity")
public class UserEntity {

    @Id
    private String username;

    @Column(name = "email_id", unique = true)
    private String emailId;

    @Column(nullable = false)
    private String password;

    @Column(name = "mobile_number")
    private String mobileNumber;

    @Column(nullable = false)
    private String roles;

    @OneToMany(mappedBy = "userEntity", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<RefreshTokenEntity> refreshToken;
}
