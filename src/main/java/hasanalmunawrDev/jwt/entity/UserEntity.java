package hasanalmunawrDev.jwt.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
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
}
