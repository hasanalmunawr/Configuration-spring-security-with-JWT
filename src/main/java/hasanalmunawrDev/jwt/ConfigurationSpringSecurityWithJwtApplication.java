package hasanalmunawrDev.jwt;

import hasanalmunawrDev.jwt.config.UserConfig;
import hasanalmunawrDev.jwt.config.userConfig.InitialUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ConfigurationSpringSecurityWithJwtApplication {


	public static void main(String[] args) {
		SpringApplication.run(ConfigurationSpringSecurityWithJwtApplication.class, args);
	}

}
