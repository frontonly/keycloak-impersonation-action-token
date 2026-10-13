package twobiers.keycloak;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * End-to-end test of the impersonation link flow against a real Keycloak: requesting a link must not
 * impersonate anyone, redeeming it must create a session for the target user, and redeeming it twice must
 * be rejected. The last part is what pins the single-use/revocation behaviour, which differs between
 * Keycloak lines (see {@code ActionTokenRevocation}).
 *
 * <p>The image under test is {@code -Dkeycloak.image=...}; the {@code keycloak-26.6} Maven profile sets it
 * to the 26.6.x server while compiling against the 26.6.x SPIs.
 */
@Testcontainers
public class ImpersonationFlowTest {

	private static final String REALM = "demo";
	private static final String OPERATOR = "operator";
	private static final String TARGET_USER = "alice";
	private static final String PASSWORD = "password";

	@Container
	private static final KeycloakContainer keycloak = new KeycloakContainer(
			System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:nightly"))
			.withDefaultProviderClasses();

	private static String authServerUrl;
	private static String targetUserId;
	private static Keycloak operator;

	@BeforeAll
	static void beforeAll() {
		authServerUrl = keycloak.getAuthServerUrl();
		Keycloak admin = keycloak.getKeycloakAdminClient();

		RealmRepresentation realm = new RealmRepresentation();
		realm.setRealm(REALM);
		realm.setEnabled(true);
		admin.realms().create(realm);
		RealmResource realmResource = admin.realm(REALM);

		targetUserId = createUser(realmResource, TARGET_USER);
		String operatorId = createUser(realmResource, OPERATOR);

		// "impersonation" is the realm-management role the extension's
		// UserPermissionEvaluator#requireImpersonate checks for.
		ClientRepresentation realmManagement = realmResource.clients().findByClientId("realm-management").get(0);
		RoleRepresentation impersonation = realmResource.clients().get(realmManagement.getId())
				.roles().get("impersonation").toRepresentation();
		realmResource.users().get(operatorId).roles()
				.clientLevel(realmManagement.getId()).add(List.of(impersonation));

		operator = Keycloak.getInstance(authServerUrl, REALM, OPERATOR, PASSWORD, "admin-cli");
	}

	@AfterAll
	static void afterAll() {
		operator.close();
	}

	@Test
	public void redemptionImpersonatesTargetUser() throws IOException {
		String link = requestImpersonationLink(targetUserId);

		Response redemption = given().redirects().follow(false).get(link);
		assertEquals(302, redemption.statusCode(), redemption.asString());

		String identity = redemption.getCookie("KEYCLOAK_IDENTITY");
		assertNotNull(identity, "redeeming the link must set the identity cookie");
		assertEquals(targetUserId, identityCookieSubject(identity),
				"session created by the link belongs to the impersonated user");
	}

	@Test
	public void redemptionIsSingleUse() {
		String link = requestImpersonationLink(targetUserId);

		assertEquals(302, given().redirects().follow(false).get(link).statusCode());

		Response replay = given().redirects().follow(false).get(link);
		assertEquals(400, replay.statusCode(), "replaying a redeemed link must be rejected: " + replay.asString());
		assertNull(replay.getCookie("KEYCLOAK_IDENTITY"), "replay must not issue another session");
	}

	private static String requestImpersonationLink(String userId) {
		return given()
				.baseUri(authServerUrl)
				.auth().oauth2(operatorToken())
				.contentType(ContentType.JSON)
				.post("/admin/realms/" + REALM + "/impersonation/users/" + userId)
				.then()
				.statusCode(200)
				.extract().jsonPath().getString("redirect");
	}

	/**
	 * Redeeming a link terminates the impersonator's own session, which invalidates the access token the
	 * link was requested with, so a fresh grant is obtained for every request.
	 */
	private static String operatorToken() {
		operator.tokenManager().grantToken();
		return operator.tokenManager().getAccessTokenString();
	}

	/**
	 * The identity cookie is a JWT whose subject is the user the session belongs to.
	 */
	private static String identityCookieSubject(String identityCookie) throws IOException {
		String payload = identityCookie.split("\\.")[1];
		payload += "=".repeat((4 - payload.length() % 4) % 4);
		byte[] decoded = Base64.getUrlDecoder().decode(payload);
		return new ObjectMapper().readTree(decoded).get("sub").asText();
	}

	private static String createUser(RealmResource realmResource, String username) {
		UserRepresentation user = new UserRepresentation();
		user.setUsername(username);
		user.setEnabled(true);
		// The declarative user profile of current Keycloak versions requires email and name; a user without
		// them cannot log in via direct grant ("Account is not fully set up").
		user.setEmail(username + "@example.test");
		user.setFirstName(username);
		user.setLastName("Tester");
		user.setEmailVerified(true);

		String userId;
		try (jakarta.ws.rs.core.Response response = realmResource.users().create(user)) {
			assertEquals(201, response.getStatus());
			userId = CreatedResponseUtil.getCreatedId(response);
		}

		CredentialRepresentation credential = new CredentialRepresentation();
		credential.setType(CredentialRepresentation.PASSWORD);
		credential.setValue(PASSWORD);
		credential.setTemporary(false);
		realmResource.users().get(userId).resetPassword(credential);

		return userId;
	}
}
