package hasanalmunawrDev.jwt.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "refresh_token", nullable = false, length = 10000)
    private String refreshToken;

    private boolean revoked;

    private boolean isExpired;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "username")
    private UserEntity userEntity;
}
