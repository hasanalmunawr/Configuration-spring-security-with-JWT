package hasanalmunawrDev.jwt.config;

import hasanalmunawrDev.jwt.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@RequiredArgsConstructor
public class UserConfig implements UserDetails {

    private final UserEntity userEntity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String role = userEntity.getRoles();
        // Map it to a GrantedAuthority:
        return Collections.singletonList(new SimpleGrantedAuthority(role));
//        return Arrays
//                .stream(userEntity
//                        .getRoles()
//                        .split(","))
//                .map(SimpleGrantedAuthority::new)
//                .toList();
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
