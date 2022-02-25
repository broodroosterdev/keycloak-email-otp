package niroj.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

/**
 * @author Niko Köbler, https://www.n-k.de, @niroj
 */
public class EmailAuthenticatorFactory implements AuthenticatorFactory {
	public static final String CODE_LENGTH = "6";
	public static final String TIME_TO_LIVE = "300";
	public static final String SIMULATION_MODE = "false";

	@Override
	public String getId() {
		return "email-authenticator";
	}

	@Override
	public String getDisplayType() {
		return "Email Authentication";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via Email to the users email address.";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return new AuthenticationExecutionModel.Requirement[] {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.ALTERNATIVE,
			AuthenticationExecutionModel.Requirement.DISABLED,
		};
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return Arrays.asList(
			new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, CODE_LENGTH),
			new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, TIME_TO_LIVE),
			new ProviderConfigProperty("simulation", "Simulation mode", "In simulation mode, the EMAIL won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, SIMULATION_MODE)
		);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return new EmailAuthenticator();
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

}
