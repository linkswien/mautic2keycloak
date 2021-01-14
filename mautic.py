from requests_toolbelt import sessions
from requests.compat import urljoin
from base64 import b64encode
import codecs


class MauticAPIException(Exception):
	"""Exception class for errors raised by Mautic API"""
	pass


class MauticAPI:
	session = None

	def __init__(self, host, username, password):
		self.session = sessions.BaseUrlSession(base_url=urljoin(host, 'api/'))
		token = codecs.decode(b64encode(codecs.encode(f'{username}:{password}')))

		self.session.headers.update({
			'User-Agent': 'mautic2keycloak',
			'Accept': 'application/json',
			'Authorization': f'Basic {token}'
		})

	def get_request(self, endpoint, **params):
		"""Sends formatted GET request to API endpoint"""

		req = self.session.get(endpoint, params=params)
		req.raise_for_status()
		json_res = req.json()

		if 'errors' in json_res:
			raise MauticAPIException(json_res['errors'][0]['message'])

		return json_res

	def patch_request(self, endpoint, data):
		"""Sends formatted PATCH request to API endpoint"""

		req = self.session.patch(endpoint, json=data)
		req.raise_for_status()
		json_res = req.json()

		if 'errors' in json_res:
			raise MauticAPIException(json_res['errors'][0]['message'])

		return json_res

	def _pagination_iter(self, more_func, *args, **kwargs):
		"""Turns a paginated API call into an iterable"""

		offset = 0
		page = []

		while True:
			if not page:
				page = more_func(offset, *args, **kwargs)
				if not page:
					break

				offset += len(page)

			yield page.pop()

	def _get_contacts_page(self, offset, search=''):
		data = self.get_request('contacts', minimal=True, start=offset, search=search)
		if not data['contacts']:
			return None

		return list(data['contacts'].values())

	def get_contacts(self, search=''):
		"""Requests Mautic contacts and turns API pagination into a generator"""

		return self._pagination_iter(self._get_contacts_page, search=search)

	def update_contact(self, id, data):
		return self.patch_request(f'contacts/{id}/edit', data)
