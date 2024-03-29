package hasanalmunawrDev.jwt.config.jwt;

import hasanalmunawrDev.jwt.config.RSAKeyRecord;
import jakarta.servlet.*;

import java.io.IOException;

public class JwtAccessTokenFilter implements Filter {
    public JwtAccessTokenFilter(RSAKeyRecord rsaKeyRecord, Object p1) {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

    }
}
