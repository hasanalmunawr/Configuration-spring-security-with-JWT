package hasanalmunawrDev.jwt.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

public record UserRegrestationDto(
        @NotEmpty(message = "Username must not be empty")
        String username,
        String mobileNumber,
        @NotEmpty(message = "email must not be empty")
        @Email(message = "Invalid email format")
        String email,
        @NotBlank(message = "Password must not be blank")
        String password,
        @NotEmpty(message = "Role must not be empty")
        String role
) {
}
