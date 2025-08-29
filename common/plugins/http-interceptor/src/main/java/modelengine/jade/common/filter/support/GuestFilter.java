package modelengine.jade.common.filter.support;

import modelengine.fit.http.server.HttpClassicServerRequest;
import modelengine.fit.http.server.HttpClassicServerResponse;
import modelengine.fit.http.server.HttpServerFilter;
import modelengine.fit.http.server.HttpServerFilterChain;
import modelengine.fitframework.annotation.Component;
import modelengine.fitframework.annotation.Order;
import modelengine.fitframework.annotation.Scope;
import modelengine.fitframework.inspection.Validation;
import modelengine.fitframework.log.Logger;
import modelengine.jade.authentication.AuthenticationService;
import modelengine.jade.authentication.context.HttpRequestUtils;
import modelengine.jade.authentication.context.UserContext;
import modelengine.jade.authentication.context.UserContextHolder;

import java.util.Collections;
import java.util.List;

/**
 * 表示游客访问 http 请求过滤器。
 *
 * @author 鲁为
 * @since 2025-08-28
 */
@Component
public class GuestFilter implements HttpServerFilter {
    private final AuthenticationService authenticationService;
    private static final Logger log = Logger.get(LoginFilter.class);

    /**
     * 用用户认证服务 {@link AuthenticationService} 构造 {@link GuestFilter}。
     *
     * @param authenticationService 表示用户认证服务的 {@link AuthenticationService}。
     */
    public GuestFilter(AuthenticationService authenticationService) {
        this.authenticationService = Validation.notNull(authenticationService, "The auth service cannot be null.");
    }

    @Override
    public String name() {
        return "GuestFilter";
    }

    @Override
    public int priority() {
        return Order.HIGHEST;
    }

    @Override
    public List<String> matchPatterns() {
        return Collections.singletonList("/v1/api/guest/**");
    }

    @Override
    public List<String> mismatchPatterns() {
        return Collections.singletonList("");
    }

    @Override
    public void doFilter(HttpClassicServerRequest request, HttpClassicServerResponse response,
            HttpServerFilterChain chain) {
        UserContext operationContext = new UserContext(this.authenticationService.getUserName(request),
                HttpRequestUtils.getUserIp(request),
                HttpRequestUtils.getAcceptLanguages(request));
        UserContextHolder.apply(operationContext, () -> chain.doFilter(request, response));
    }

    @Override
    public Scope scope() {
        return Scope.GLOBAL;
    }
}
