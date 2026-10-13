package twobiers.keycloak.actiontoken;

import java.net.URI;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.keycloak.TokenVerifier;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.DefaultActionTokenKey;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectKeyModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.messages.Messages;

import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_ID;
import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_USERNAME;

public class ImpersonateActionTokenHandler extends AbstractActionTokenHandler<ImpersonateActionToken> {

	// Upstream Keycloak resolves this against the theme message key Messages.IMPERSONATE_ERROR
	// ("impersonateError"), which does not exist in the targeted Keycloak release yet. We inline the
	// English text so the error page renders a sensible message without a custom theme.
	private static final String IMPERSONATE_ERROR_MESSAGE = "Error happened while impersonating user";

	public ImpersonateActionTokenHandler() {
		super(ImpersonateActionToken.TOKEN_TYPE, ImpersonateActionToken.class, Messages.EXPIRED_ACTION,
				EventType.IMPERSONATE, Errors.INVALID_TOKEN);
	}

	@Override
	public TokenVerifier.Predicate<? super ImpersonateActionToken>[] getVerifiers(
			ActionTokenContext<ImpersonateActionToken> tokenContext) {
		return TokenUtils.predicates();
	}

	@Override
	public Response handleToken(ImpersonateActionToken token, ActionTokenContext<ImpersonateActionToken> tokenContext) {
		KeycloakSession session = tokenContext.getSession();
		RealmModel realm = tokenContext.getRealm();
		UserModel user = session.users().getUserById(realm, token.getUserId());
		ClientConnection clientConnection = tokenContext.getClientConnection();
		EventBuilder event = tokenContext.getEvent();
		event.event(EventType.IMPERSONATE)
				.detail(Details.IMPERSONATOR_REALM, token.getImpersonatorRealm())
				.detail(Details.IMPERSONATOR, token.getImpersonatorUsername());

		// Normally, action tokens are invalidated after the intended required action is
		// executed. However, since
		// impersonation doesn't have a required action and is instead executed
		// immediately when the token is handled,
		// we need to invalidate the token here to prevent it from being used multiple
		// times.
		if (!invalidateActionToken(session, token.serializeKey(), 0L)) {
			return handleImpersonationError(tokenContext, Errors.EXPIRED_CODE, Status.BAD_REQUEST);
		}

		if (user == null) {
			return handleImpersonationError(tokenContext, Errors.USER_NOT_FOUND, Status.NOT_FOUND);
		}
		if (!user.isEnabled()) {
			return handleImpersonationError(tokenContext, Errors.USER_DISABLED, Status.BAD_REQUEST);
		}
		if (user.getServiceAccountClientLink() != null) {
			return handleImpersonationError(tokenContext, Errors.NOT_ALLOWED, Status.BAD_REQUEST);
		}

		// When impersonating within the same realm, the administrator's own session is terminated here (at redemption
		// time), because their identity cookie is about to be replaced with the impersonated user's session. The
		// session to terminate is carried in the token instead of being resolved from the request context, as this
		// handler opts out of the identity-cookie authentication performed by LoginActionsServiceChecks#checkIsUserValid.
		if (token.getImpersonatorSessionId() != null) {
			UserSessionModel impersonatorSession = session.sessions().getUserSession(realm, token.getImpersonatorSessionId());
			if (impersonatorSession != null && !impersonatorSession.getUser().getId().equals(user.getId())) {
				AuthenticationManager.expireIdentityCookie(session);
				AuthenticationManager.expireRememberMeCookie(session);
				AuthenticationManager.expireAuthSessionCookie(session);
				AuthenticationManager.backchannelLogout(session, realm, impersonatorSession, session.getContext().getUri(),
						clientConnection, session.getContext().getHttpRequest().getHttpHeaders(), true);
			}
		}

		UserSessionModel userSession = new UserSessionManager(session).createUserSession(realm, user,
				user.getUsername(),
				clientConnection.getRemoteHost(), "impersonate", false, null, null);
		userSession.setNote(IMPERSONATOR_ID.toString(), token.getImpersonatorId());
		userSession.setNote(IMPERSONATOR_USERNAME.toString(), token.getImpersonatorUsername());

		AuthenticationManager.createLoginCookie(session, realm, userSession.getUser(), userSession,
				session.getContext().getUri(), clientConnection);
		URI redirect = URI.create(token.getRedirectUri());

		event.session(userSession)
				.user(user)
				.success();

		// The fresh authentication session created for processing this action token has served its purpose and would
		// otherwise linger (together with its browser cookie) until it times out.
		removeAuthenticationSession(tokenContext);

		return Response.status(Response.Status.FOUND)
				.location(redirect)
				.build();
	}

	@Override
	public boolean canUseTokenRepeatedly(ImpersonateActionToken token,
			ActionTokenContext<ImpersonateActionToken> tokenContext) {
		return false;
	}

	private Response handleImpersonationError(ActionTokenContext<?> tokenContext, String error, Status status) {
		removeAuthenticationSession(tokenContext);

		tokenContext.getEvent().event(EventType.IMPERSONATE).error(error);

		return ErrorPage.error(tokenContext.getSession(), null, status, IMPERSONATE_ERROR_MESSAGE);
	}

	private static void removeAuthenticationSession(ActionTokenContext<?> tokenContext) {
		if (tokenContext.getAuthenticationSession() != null) {
			new AuthenticationSessionManager(tokenContext.getSession())
					.removeAuthenticationSession(tokenContext.getRealm(), tokenContext.getAuthenticationSession(),
							true);
		}
	}

	private boolean invalidateActionToken(KeycloakSession session, String actionTokenKeyToInvalidate,
			long skewSeconds) {
		SingleUseObjectKeyModel actionTokenKey = DefaultActionTokenKey.from(actionTokenKeyToInvalidate);
		if (actionTokenKey == null) {
			return false;
		}
		long lifespanSeconds = Math.max(1L, actionTokenKey.getExp() - Time.currentTime() + skewSeconds);
		return ActionTokenRevocation.revoke(session, actionTokenKeyToInvalidate, lifespanSeconds);
	}
}
