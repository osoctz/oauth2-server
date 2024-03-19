package cn.metaq.oauth2.server.config;

import cn.metaq.oauth2.server.security.userdetails.CustomUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

import java.util.Optional;

/**
 * JWT 自定义字段
 *
 * @author tom
 * @since 3.0.0
 */
@Configuration
public class JwtTokenClaimsConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && context.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
                // Customize headers/claims for access_token
                Optional.ofNullable(context.getPrincipal().getPrincipal()).ifPresent(principal -> {
                    JwtClaimsSet.Builder claims = context.getClaims();
                    if (principal instanceof CustomUserDetails) {

                        CustomUserDetails userDetails= (CustomUserDetails) principal;
                        // 系统用户添加自定义字段
                        String userId = userDetails.getUserId();
                        // 添加系统用户ID
                        claims.claim("user_id", userId);
                    }
                });
            }
        };
    }

}
