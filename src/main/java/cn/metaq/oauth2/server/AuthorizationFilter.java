package cn.metaq.oauth2.server;

import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

/**
 * @author zantang
 * @version 1.0
 * @description TODO
 * @date 2021/4/29 2:01 下午
 */
@WebFilter(filterName = "authorizationFilter", urlPatterns = {"/authorize"})
@Log4j2
public class AuthorizationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @SneakyThrows
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        // String requestUri = request.getRequestURI();

        Enumeration<String> headers = request.getHeaderNames();

        while (headers.hasMoreElements()) {

            log.info("header:{}", headers.nextElement());
        }

        String redirect_uri = request.getParameter("redirect_uri");
        response.sendRedirect(redirect_uri + "?code=112233");
    }

    @Override
    public void destroy() {

    }
}
