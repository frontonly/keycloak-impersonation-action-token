package twobiers.keycloak.actiontoken;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

/**
 * Revokes an action token so it cannot be redeemed twice.
 *
 * <p>Keycloak 26.6 has no dedicated revoked-token store, so
 * {@code LoginActionsServiceChecks#checkTokenWasNotUsedYet} looks the serialized action token key up in the
 * single-use object store under the {@link SingleUseObjectProvider#REVOKED_KEY} ({@code ".revoked"}) suffix.
 * Revoking therefore means inserting exactly that key; {@code putIfAbsent} reports whether this call was the
 * one that revoked it. The same layout is what {@code RevokedTokenProvider} uses internally in 26.7, which
 * is also the only Keycloak-line specific code in this build: {@code pom.xml} picks either this file or its
 * counterpart in {@code src/main/java-kc26.7}.
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
		return session.singleUseObjects()
				.putIfAbsent(actionTokenKey + SingleUseObjectProvider.REVOKED_KEY, lifespanSeconds);
	}
}
