package dasniko.keycloak.user;

import dasniko.keycloak.user.external.CredentialData;
import dasniko.keycloak.user.external.Peanut;
import dasniko.keycloak.user.external.PeanutsClient;
import dasniko.keycloak.user.external.PeanutsClientSimpleHttp;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * @author Niko Köbler, http://www.n-k.de, @dasniko
 */
@Slf4j
public class PeanutsUserProvider implements UserStorageProvider,
	UserLookupProvider.Streams, UserQueryProvider.Streams,
	CredentialInputUpdater, CredentialInputValidator,
	UserRegistrationProvider {

	private final KeycloakSession session;
	private final ComponentModel model;
	private final PeanutsClient client;

	protected Map<String, UserModel> loadedUsers = new HashMap<>();

	public PeanutsUserProvider(KeycloakSession session, ComponentModel model) {
		this.session = session;
		this.model = model;
		this.client = new PeanutsClientSimpleHttp(session, model);
	}

	@Override
	public void close() {
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		return PasswordCredentialModel.TYPE.equals(credentialType);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		return supportsCredentialType(credentialType);
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
		if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
			return false;
		}
		
		if (user.getId()=="Test1") {return true;}
		if (user.getId()=="Test10") {return true;}
		return false;
	}

	@Override
	public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
		log.debug("Try to update credentials type {} for user {}.", input.getType(), user.getId());
		if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
			return false;
		}
		return true;
	}

	@Override
	public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
	}

	@Override
	public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
		return Set.of();
	}

	@Override
	public UserModel getUserById(RealmModel realm, String id) {
		log.debug("getUserById: {}", id);
		return findUser(realm, StorageId.externalId(id));
	}

	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
		log.debug("getUserByUsername: {}", username);
		return findUser(realm, username);
	}

	@Override
	public UserModel getUserByEmail(RealmModel realm, String email) {
		log.debug("getUserByEmail: {}", email);
		return findUser(realm, email);
	}

	private UserModel findUser(RealmModel realm, String identifier) {
		return new UserModel();
	}

	@Override
	public int getUsersCount(RealmModel realm) {
		return 2;
	}

	@Override
	public Stream<UserModel> getUsersStream(RealmModel realm, Integer firstResult, Integer maxResults) {
		log.debug("getUsersStream, first={}, max={}", firstResult, maxResults);
		return toUserModelStream(client.getPeanuts(null, firstResult, maxResults), realm);
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
		log.debug("searchForUserStream, search={}, first={}, max={}", search, firstResult, maxResults);
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
		log.debug("searchForUserStream, params={}, first={}, max={}", params, firstResult, maxResults);
		return Stream.empty();
	}

	private Stream<UserModel> toUserModelStream(List<Peanut> peanuts, RealmModel realm) {
		log.debug("Received {} users from provider", peanuts.size());
		return peanuts.stream().map(user -> new UserAdapter(session, realm, model, user));
	}

	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
		return Stream.empty();
	}

	@Override
	public UserModel addUser(RealmModel realm, String username) {
		return null;
	}

	@Override
	public boolean removeUser(RealmModel realm, UserModel user) {
		return false;
	}
}
