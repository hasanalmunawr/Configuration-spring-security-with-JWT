package hasanalmunawrDev.jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import hasanalmunawrDev.jwt.entity.TokenType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthResponseDto {

    @JsonProperty("acces_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenType tokenType;

    private String username;
}

