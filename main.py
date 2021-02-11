#!/usr/bin/python3

from keycloak import KeycloakAdmin
from keycloak.urls_patterns import URL_ADMIN_USER_REALM_ROLES
from keycloak.exceptions import KeycloakGetError, raise_error_from_response
from mautic import MauticAPI
from unidecode import unidecode
from operator import itemgetter
from traceback import print_exc
import datetime
import yaml
import json


class SyncException(Exception):
	pass


class MauticKeycloakSyncer:
	def __init__(self, config):
		self.config = config
		self.mautic = MauticAPI(**config['mautic_auth'])
		self.keycloak = KeycloakAdmin(**config['keycloak_auth'])

		# Any Keycloak users whose ID is not in this set by the time we reach
		# pass 2 will be deleted.
		self.acceptable_keycloak_ids = set()

		# Retrieve realm roles for use in assign_keycloak_roles
		roles = self.keycloak.get_realm_roles()
		self.realm_roles = {role['name']: role for role in roles}

	def prepare_keycloak_data(self, contact, sync_time):
		"""
		Convert Mautic contact data into a user data dict suitable for passing to
		a Keycloak API request
		"""

		fields = contact['fields']['core']

		return {
			'email': fields['email']['value'],
			'enabled': True,
			'firstName': fields['firstname']['value'],
			'lastName': fields['lastname']['value'],
			'attributes': {'mautic_id': contact['id'], 'last_sync': sync_time},
		}

	def assign_keycloak_roles(self, keycloak_id, contact):
		"""
		Assign/remove the necessary realm roles of a Keycloak user based on the
		custom contact fields
		"""

		role_names = set(self.config['mautic']['default_roles'])

		for field, role in self.config['mautic'].get('boolean_role_fields', {}).items():
			if contact['fields']['professional'][field]['value'] == '1':
				role_names.add(role)

		for field in self.config['mautic'].get('role_fields', []):
			values = contact['fields']['professional'][field]['value']
			if values:
				role_names |= set(values.split('|'))

		for field, prefix in self.config['mautic'].get('prefixed_role_fields', {}).items():
			value = contact['fields']['professional'][field]['value']
			if value:
				role_names.add(f'{prefix}{value}')

		want_roles = set(filter(lambda x: x in self.realm_roles, role_names))

		have_roles = self.keycloak.get_realm_roles_of_user(keycloak_id)
		have_roles = set(map(itemgetter('name'), have_roles))

		remove_roles = have_roles - want_roles
		add_roles = want_roles - have_roles

		if remove_roles:
			print('Remove roles:', remove_roles)
			remove_roles = map(lambda x: self.realm_roles[x], remove_roles)

			# API method missing from library
			params_path = {"realm-name": self.keycloak.realm_name, 'id': keycloak_id}
			data_raw = self.keycloak.raw_delete(URL_ADMIN_USER_REALM_ROLES.format(**params_path),
				data=json.dumps(list(remove_roles)))
			raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

		if add_roles:
			print('Add roles:', add_roles)
			add_roles = map(lambda x: self.realm_roles[x], add_roles)
			self.keycloak.assign_realm_roles(keycloak_id, 'dummy', list(add_roles))

	def generate_username(self, contact):
		fields = contact['fields']['core']
		first_name = fields['firstname']['value']
		last_name = fields['lastname']['value']
		username = f'{first_name[0]}.{last_name}'.lower()

		# Special handling for German non-ascii chars
		for orig, new in {'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss', ' ': '-'}.items():
			username = username.replace(orig, new)

		# Remove remaining utf8 chars
		return unidecode(username)

	def create_keycloak_user(self, sync_time, contact):
		"""
		Creates a new Keycloak user based on the user data in `contact`
		"""

		kc_data = self.prepare_keycloak_data(contact, sync_time)
		kc_data['username'] = self.generate_username(contact)

		print(f'Creating user {kc_data["firstName"]} {kc_data["lastName"]}')

		try:
			keycloak_id = self.keycloak.create_user(kc_data, exist_ok=False)
		except KeycloakGetError as e:
			if e.response_code == 409:
				# User exists
				# FIXME reroll username and retry
				raise SyncException('Username conflict')
			else:
				# Reraise for other API errors
				raise e

		self.assign_keycloak_roles(keycloak_id, contact)

		# Trigger password reset / username config email
		self.keycloak.send_update_account(user_id=keycloak_id, lifespan=604800,
			payload=json.dumps(['UPDATE_PASSWORD', 'UPDATE_PROFILE']))

		self.mautic.update_contact(contact['id'], {
			'keycloak_id': keycloak_id,
			'keycloak_last_sync': sync_time,
		})

		return keycloak_id

	def update_keycloak_user(self, sync_time, contact):
		"""
		Updates an existing Keycloak user with the Keycloak ID in `contact`
		based on the data ìn `contact`
		"""

		kc_data = self.prepare_keycloak_data(contact, sync_time)

		print(f'Updating user {kc_data["firstName"]} {kc_data["lastName"]}')
		keycloak_id = contact['fields']['professional']['keycloak_id']['value']

		self.keycloak.update_user(keycloak_id, payload=kc_data)
		self.assign_keycloak_roles(keycloak_id, contact)
		self.mautic.update_contact(contact['id'], {'keycloak_last_sync': sync_time})

	def sync_contact(self, contact):
		"""
		Synchronizes a single Mautic contact with Keycloak, either creating
		a new Keycloak user or updating an existing one in the process.

		Also updates the Mautic contact with the attributes (ID, last synced)
		of the Keycloak user.
		"""

		core_fields = contact['fields']['core']
		prof_fields = contact['fields']['professional']

		if not all({core_fields['firstname']['value'], core_fields['lastname']['value'],
			core_fields['email']['value']}):

			raise SyncException('Missing one of (First name, last name, email)')

		sync_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
		# Need to add time since our final save increases last_modified again
		# FIXME Maybe find a nicer workaround for this, but not sure if possible
		sync_time += datetime.timedelta(seconds=20)
		sync_time = sync_time.isoformat()

		# If Mautic contact has no keycloak_id set, create new Keycloak user
		if not prof_fields['keycloak_id']['value']:
			new_kid = self.create_keycloak_user(sync_time, contact)
			self.acceptable_keycloak_ids.add(new_kid)
			return

		self.acceptable_keycloak_ids.add(prof_fields['keycloak_id']['value'])

		# Otherwise, check if last_modified is newer than last_sync, and if so, update Keycloak user
		last_sync = prof_fields['keycloak_last_sync']['value']
		if not last_sync:
			raise SyncException('Mautic contact has keycloak_id, but no keycloak_last_sync')

		last_sync = datetime.datetime.fromisoformat(last_sync).replace(tzinfo=datetime.timezone.utc)
		last_modified = datetime.datetime.fromisoformat(contact['dateModified'])

		if last_modified >= last_sync:
			self.update_keycloak_user(sync_time, contact)

	def run(self):
		print('Pass 1: Creating and updating Mautic contacts in Keycloak\n')

		for contact in self.mautic.get_contacts(search=self.config['mautic']['transfer_constraint']):
			try:
				self.sync_contact(contact)
			except Exception as e:
				print(f'Could not sync contact #{contact["id"]}: {e}')
				print_exc()

		print('\nPass 2: Deleting Keycloak users not in Mautic\n')
		for user in self.keycloak.get_users():
			if user['id'] not in self.acceptable_keycloak_ids:
				print(f'Deleting keycloak user {user["username"]} ({user.get("firstName")} {user.get("lastName")})')
				self.keycloak.delete_user(user['id'])


def main():
	with open('config.yml', 'r') as file:
		config = yaml.safe_load(file)

	syncer = MauticKeycloakSyncer(config)
	syncer.run()


if __name__ == '__main__':
	main()
