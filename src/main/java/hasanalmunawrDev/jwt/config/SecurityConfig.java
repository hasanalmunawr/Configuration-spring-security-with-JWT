package hasanalmunawrDev.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @Autowired
    private UserManagerConfig userManagerConfig;

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/api/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .userDetailsService(userManagerConfig)
                .formLogin(withDefaults())
                .httpBasic(withDefaults())
                .build();
    }

//    @Bean
//    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity
//                .userDetailsService(userManagerConfig)
//                .authorizeHttpRequests( auth -> {
//                    auth.requestMatchers(AntPathRequestMatcher.antMatcher("/api/**")).permitAll();
//                    auth.anyRequest().authenticated();
//                })
//                // ignore cross-site-request-forgery(CSRF) , though you should never disable it, but for to access some tools we need to disable it
//                .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/api/**")))
//                // important to display h2-console in frame in browser.
//                .headers(headers -> headers.frameOptions(withDefaults()).disable())
//                .formLogin(withDefaults())
//                .httpBasic(withDefaults()) // if formLogin is not available, then we can use it.
//                .build();
//    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
