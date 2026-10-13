package twobiers.keycloak.actiontoken;

import org.keycloak.models.KeycloakSession;

/**
 * Revokes an action token so it cannot be redeemed twice.
 *
 * <p>Keycloak 26.7 introduced a dedicated revoked-token store ({@code KeycloakSession#revokedTokens()}) and
 * {@code LoginActionsServiceChecks#checkTokenWasNotUsedYet} consults it, so that is what revocation has to
 * write to here. See {@code src/main/java-kc26.6} for the same class compiled against 26.6.x, where the
 * single-use object store is still the only place the check looks at. The two files are the only
 * Keycloak-line specific code in this build; {@code pom.xml} picks one of them.
 */
final class ActionTokenRevocation {

	private ActionTokenRevocation() {
	}

	/**
	 * @param actionTokenKey  serialized action token key to revoke
	 * @param lifespanSeconds how long the revocation must be remembered (at least until the token itself expires)
	 * @return {@code true} if this call performed the revocation, {@code false} if the token was revoked before
	 */
	static boolean revoke(KeycloakSession session, String actionTokenKey, long lifespanSeconds) {
		return session.revokedTokens().put(actionTokenKey, lifespanSeconds);
	}
}
