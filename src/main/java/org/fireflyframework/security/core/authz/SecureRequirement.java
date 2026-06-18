/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.core.authz;

import org.fireflyframework.security.api.annotation.Secure;

import java.util.List;

/**
 * Framework-neutral view of a {@link Secure} requirement, decoupling the authorization evaluator
 * from the annotation type so it can also be built programmatically (e.g. from a URL registry).
 */
public record SecureRequirement(
        List<String> roles,
        List<String> scopes,
        List<String> permissions,
        boolean requireAllRoles,
        boolean requireAllScopes,
        boolean requireAllPermissions,
        String expression
) {

    public SecureRequirement {
        roles = roles == null ? List.of() : List.copyOf(roles);
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
        expression = expression == null ? "" : expression;
    }

    public static SecureRequirement from(Secure secure) {
        return new SecureRequirement(
                List.of(secure.roles()),
                List.of(secure.scopes()),
                List.of(secure.permissions()),
                secure.requireAllRoles(),
                secure.requireAllScopes(),
                secure.requireAllPermissions(),
                secure.expression());
    }

    public boolean isEmpty() {
        return roles.isEmpty() && scopes.isEmpty() && permissions.isEmpty() && expression.isBlank();
    }
}
