package hasanalmunawrDev.jwt.config;

import hasanalmunawrDev.jwt.config.UserConfig;
import hasanalmunawrDev.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserManagerConfig implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmailId(username)
                .map(UserConfig::new)
                .orElseThrow(() -> new UsernameNotFoundException("Email "+username+" Does not Exist"));
    }
}
