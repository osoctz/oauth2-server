package cn.metaq.oauth2.server;

import lombok.Data;

/**
 * @author zantang
 * @version 1.0
 * @description TODO
 * @date 2021/5/21 11:15 上午
 */
@Data
public class AccessTokenResponse {

    private String access_token;
    private String expires_in;
    private String refresh_token;
    private String uid;
}
