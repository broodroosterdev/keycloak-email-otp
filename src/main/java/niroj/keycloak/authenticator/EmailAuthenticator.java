package niroj.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;


// email provider from keycloak
import org.keycloak.email.DefaultEmailSenderProvider;

/**
 * @author Niko Köbler, https://www.n-k.de, @niroj
 */
public class EmailAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-email.ftl";
	private static final Logger logger = Logger.getLogger(EmailAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		Map<String, String> configMap;;
		if(config == null){
			configMap = new HashMap<>();
			configMap.put("length", EmailAuthenticatorFactory.CODE_LENGTH);
			configMap.put("ttl", EmailAuthenticatorFactory.TIME_TO_LIVE);
			configMap.put("simulation", EmailAuthenticatorFactory.SIMULATION_MODE);
		} else {
			configMap = config.getConfig();
		}

		int length = Integer.parseInt(configMap.get("length"));
		int ttl = Integer.parseInt(configMap.get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String emailAuthText = theme.getMessages(locale).getProperty("emailAuthText");
			String emailText = String.format(emailAuthText, code, Math.floorDiv(ttl, 60));

			boolean simulateEmail = Boolean.parseBoolean(configMap.get("simulation"));
			if(simulateEmail){
				logger.warn(String.format(
						"***** SIMULATION MODE ***** Would send email to %s with content: %s",
						user.getEmail(),
						emailText
				));
			} else {
				DefaultEmailSenderProvider senderProvider = new DefaultEmailSenderProvider(session);
				senderProvider.send(
					session.getContext().getRealm().getSmtpConfig(),
					user,
					"2FA Authentication",
					emailText,
					emailText
				);
			}

			context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("emailAuthEmailNotSent", e.getMessage())
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("emailAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("emailAuthCodeInvalid").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return user.getEmail() != null;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
