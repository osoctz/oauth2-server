package cn.metaq.oauth2.server.provider;

import cn.metaq.oauth2.server.AccessTokenResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.UUID;

/**
 * @author zantang
 * @version 1.0
 * @description 授权服务提供者
 * @date 2021/5/21 9:17 上午
 */
@Controller
@RequestMapping("/")
public class AuthorizationProvider {


    @GetMapping(value = "getToken")
    @ResponseBody
    public AccessTokenResponse authorize(String grant_type, String client_id, String client_secret, String code) throws IOException {

        AccessTokenResponse accessTokenResponse=new AccessTokenResponse();

        accessTokenResponse.setAccess_token(UUID.randomUUID().toString());
        accessTokenResponse.setExpires_in("3600");
        accessTokenResponse.setRefresh_token(UUID.randomUUID().toString());
        accessTokenResponse.setUid("admin");

        return accessTokenResponse;
    }
}
