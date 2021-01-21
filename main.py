#!/usr/bin/python3

from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakGetError
from mautic import MauticAPI
from unidecode import unidecode
import datetime
import yaml


class SyncException(Exception):
	pass


class MauticKeycloakSyncer:
	def __init__(self, config):
		self.config = config
		self.mautic = MauticAPI(**config['mautic_auth'])
		self.keycloak = KeycloakAdmin(**config['keycloak_auth'])

		# Retrieve realm roles for use in assign_keycloak_roles
		roles = self.keycloak.get_realm_roles()
		self.realm_roles = {role['name']: role for role in roles}

	def prepare_keycloak_data(self, contact, sync_time):
		"""
		Convert Mautic contact data into a user data dict suitable for passing to
		a Keycloak API request
		"""

		fields = contact['fields']['core']
		first_name = fields['firstname']['value']
		last_name = fields['lastname']['value']
		username = f'{first_name[0]}.{last_name}'.lower()

		# Special handling for German non-ascii chars
		for orig, new in {'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss', ' ': '-'}.items():
			username = username.replace(orig, new)

		# Remove remaining utf8 chars
		username = unidecode(username)

		return {
			'email': fields['email']['value'],
			'username': username,
			'enabled': True,
			'firstName': first_name,
			'lastName': last_name,
			'attributes': {'mautic_id': contact['id'], 'last_sync': sync_time},
		}

	def assign_keycloak_roles(self, keycloak_id, contact):
		"""
		Assigns the necessary realm roles to a Keycloak user based on the
		custom contact fields

		FIXME Remove roles – Need to get roles then do delta?
		"""

		role_names = set(self.config['mautic']['default_roles'])

		for field in self.config['mautic']['role_fields']:
			values = contact['fields']['professional'][field]['value']
			if values:
				role_names |= set(values.split('|'))

		for field, prefix in self.config['mautic']['prefixed_role_fields'].items():
			value = contact['fields']['professional'][field]['value']
			if value:
				role_names.add(f'{prefix}{value}')

		role_names = filter(lambda x: x in self.realm_roles, role_names)
		roles = map(lambda x: self.realm_roles[x], role_names)
		self.keycloak.assign_realm_roles(keycloak_id, 'dummy', list(roles))

	def create_keycloak_user(self, sync_time, contact):
		"""
		Creates a new Keycloak user based on the user data in `contact`
		"""

		kc_data = self.prepare_keycloak_data(contact, sync_time)

		try:
			keycloak_id = self.keycloak.create_user(kc_data, exist_ok=False)
		except KeycloakGetError as e:
			if e.response_code == 409:
				# User exists
				# FIXME reroll username and retry
				print('exists')
				return
			else:
				# Reraise for other API errors
				raise e

		self.assign_keycloak_roles(keycloak_id, contact)
		self.mautic.update_contact(contact['id'], {
			'keycloakid': keycloak_id,
			'keycloaklastsync': sync_time,
			'keycloak_username': kc_data['username']})

	def update_keycloak_user(self, sync_time, contact):
		"""
		Updates an existing Keycloak user with the Keycloak ID in `contact`
		based on the data ìn `contact`
		"""

		kc_data = self.prepare_keycloak_data(contact, sync_time)
		keycloak_id = contact['fields']['professional']['keycloakid']['value']

		self.keycloak.update_user(keycloak_id, payload=kc_data)
		self.assign_keycloak_roles(keycloak_id, contact)
		self.mautic.update_contact(contact['id'], {'keycloaklastsync': sync_time})

	def sync_contact(self, contact):
		"""
		Synchronizes a single Mautic contact with Keycloak, either creating
		a new Keycloak user or updating an existing one in the process.

		Also updates the Mautic contact with the attributes (ID, username,
		last synced) of the Keycloak user.
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

		# If Mautic contact has no keycloakid set, create new Keycloak user
		if not prof_fields['keycloakid']['value']:
			print('no keycloak id, need to create')
			self.create_keycloak_user(sync_time, contact)
			return

		# Otherwise, check if last_modified is newer than last_sync, and if so, update Keycloak user
		last_sync = prof_fields['keycloaklastsync']['value']
		if not last_sync:
			raise SyncException('Mautic contact has keycloakid, but no keycloaklastsync')

		last_sync = datetime.datetime.fromisoformat(last_sync).replace(tzinfo=datetime.timezone.utc)
		last_modified = datetime.datetime.fromisoformat(contact['dateModified'])

		if last_modified >= last_sync:
			print('modified, need to resync.')
			self.update_keycloak_user(sync_time, contact)

	def run(self):
		for contact in self.mautic.get_contacts(search=self.config['mautic']['transfer_constraint']):
			try:
				self.sync_contact(contact)
			except Exception as e:
				print(f'Could not sync contact #{contact["id"]}: {e}')


def main():
	with open('config.yml', 'r') as file:
		config = yaml.safe_load(file)

	syncer = MauticKeycloakSyncer(config)
	syncer.run()


if __name__ == '__main__':
	main()
