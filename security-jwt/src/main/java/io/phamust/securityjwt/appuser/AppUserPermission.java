package io.phamust.securityjwt.appuser;

import lombok.Getter;

public enum AppUserPermission {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),

    USER_READ("user:read"),
    USER_UPDATE("user:update"),
    USER_CREATE("user:create"),
    USER_DELETE("user:delete");

    @Getter
    private final String permission;
    AppUserPermission(String permission) {
        this.permission = permission;
    }
}
