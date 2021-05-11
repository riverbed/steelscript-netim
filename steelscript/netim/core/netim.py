# Copyright (c) 2021 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.
import atexit
from json import dumps, JSONEncoder
import logging
import sys
import types

from steelscript.common.service import Service

__all__ = ['CustomAttribute', 'CustomAttributeValue', 'NetIM']

logging.captureWarnings(True)
logger = logging.getLogger(__name__)

class DefinitionJSONEncoder(JSONEncoder):
	def default(self, obj):
		if hasattr(obj, "attributes"):
			return obj.attributes
		else:
			return JSONEncoder.default(self, obj)

class Definition(object):
	@property
	def attributes(self):
		attrs={}

		for key, val in vars(self).items():
			if isinstance(val,list):
				l = []
				for o in val:
					if hasattr(o, "attributes"):
						l.append(o.attributes)
					else:
						l.append(o)
				attrs[key] = l
			else:
				attrs[key] = val

		return attrs

#-----

class CustomAttribute(Definition):

	def __init__(self, name, description, type='STRING', object_types=['DEVICE'], promoted=True):
	# 'type' = STRING or NUMERIC
	# 'object_type' = DEVICE, LINK, GROUP, INTERFACE

		self.name = name
		self.description = description
		self.type = type

		self.objectType = {}
		for object_type in object_types:
			self.objectType.append({'type':object_type, 'promoted':True})

class CustomAttributeValue(Definition):

	def __init__(self, device_ids = None, interface_ids = None, link_ids = None, group_ids = None, test_ids = None, 
		attribute_id = 0, value = ""):

		self.deviceIds = [] if device_ids is None else device_ids
		self.interfaceIds = [] if interface_ids is None else interface_ids
		self.linkIds = [] if link_ids is None else link_ids
		self.groupIds = [] if group_ids is None else group_ids
		self.testIds = [] if test_ids is None else test_ids
		self.attributeId = attribute_id
		self.value = value

class Device(Definition):
	
	def __init__(self, device_name, access_address, device_driver="", cli_username=""): 

		self.item = dict ()
		self.item["name"] = device_name
		self.item["displayName"] = device_name
		self.item["deviceName"] = device_name
		self.item["accessAddress"] = access_address
		self.item["description"] = "none"
		deviceAccessInfo = dict()
		deviceAccessInfo["name"] = device_name
		deviceAccessInfo["displayName"] = device_name
		deviceAccessInfo["active"] = True
		deviceAccessInfo["activeCLIConfigCollection"] = True
		deviceAccessInfo["activeMIBConfigCollection"] = True
		deviceAccessInfo["activeWMIConfigCollection"] = False
		deviceAccessInfo["activeMetricsCollection"] = False
		deviceAccessInfo["activeAWSConfigCollection"] = False
		deviceAccessInfo["deviceDriver"] = device_driver
		deviceAccessInfo["accessAddress"] = access_address
		deviceAccessInfo["cliUsername"] = cli_username
		deviceAccessInfo["hasCliPassword"] = True
		deviceAccessInfo["hasCliPrivPassword"] = False
		deviceAccessInfo["cliLoginScript"] = "InitPrompt"
		deviceAccessInfo["cliAccessMethod"] = 3
		deviceAccessInfo["snmpVersion"] = 1
		deviceAccessInfo["hasSnmpCommunityString"] = True
		deviceAccessInfo["hasSnmpV3AuthPassword"] = False
		deviceAccessInfo["hasSnmpV3PrivacyPassword"] = False
		deviceAccessInfo["wmiUsername"] = "none"
		deviceAccessInfo["wmiDomain"] = "none"
		deviceAccessInfo["awsInstanceId"] = "none"
		deviceAccessInfo["awsAccessKeyId"] = "none"
		deviceAccessInfo["awsRegion"] = "none"
		deviceAccessInfo["awsSecretAccessKey"] = "none"
		self.item["deviceAccessInfo"] = deviceAccessInfo

#-----

class NetIM(Service):
	"""NetIM Core Device API

	Responsible for DELETE, GET, POST, PUT methods against NetIM Device.

	"""
	def __init__(self, host, auth, port=8543, version=None):
		"""Initialize NetIM object.
		:param str host: name or IP address of the NetIM Core.

		:param auth: defines the authentication method and credentials
			to use to access the NetIM Core. Today, the only approach supported
			is to use UserAuth with method BasicAuth
			
			Example:
			auth = UserAuth(username,password,method=Auth.BASIC)
			netim = NetIM(host, auth=auth)

		:param port: integer, port number to connect to core

		:param str version: API version to use when communicating.
			if unspecified, this will use the latest version
		"""
		
		self.host = host
		self.auth = auth

		self.service = Service('NetIM', host=host, auth=auth, port=port,
			verify_ssl=False, versions=None,
			enable_auth_detection = False,
			supports_auth_basic=True,
			supports_auth_cookie=False,
			supports_auth_oauth=False,
			enable_services_version_detection=False)

		if version is None:
			self.version = 'v1'
		else:
			self.version = version
		
		self.base_url = f'/api/netim/{self.version}/'
		logger.info("Initialized NetIM Core Device API object with %s" % self.host)

		atexit.register(self.cleanup)

	def cleanup(self):
		# Fails in self.conn.del_headers ... self.service.logout()
		return

	# Generic API calls for resource URLs; prefer the direct calls, but allows for quick pickup of new API calls
	def _get_json(self, url):
		try:
			json_dict = self.service.conn.json_request('GET', url)
			if json_dict == None:
				logger.debug(f"Unable to retrieve resource from URL: {url}")
				return None
		except AttributeError as e:
			logger.debug(f"Attribute error: {e}")
			return None
		except:
			logger.debug(f"Exception while getting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			return None

		return json_dict

	def _get_json_from_resource_page(self, resource_url, limit, offset):
		final_url = resource_url + '?limit=' + str(limit) + '&offset=' + str(offset)
		json_dict = self._get_json(final_url)
		return json_dict

	def _get_json_from_resource(self, resource_url):
		json_dict = self._get_json(resource_url)

		# Handle error in return gracefully so script can continue
		if json_dict == None:
			return None

		# If JSON dict is first of a series of paged data, loop through getting additional pages
		if 'meta' in json_dict:
			total = json_dict['meta']['total']
			next_offset = json_dict['meta']['next_offset']
			limit = json_dict['meta']['limit']
			while next_offset < total:
				json_dict_next_page = self._get_json_from_resource_page(resource_url, limit, next_offset, verify_ssl) 
				total_items = json_dict['items']
				total_items.append(json_dict_next_page['items'])
				json_dict['items'] = total_items

				# There is a possibility of data changing while paging, so handle the possible changes
				if 'meta' in json_dict_next_page:
					total = json_dict_next_page['meta']['total']
					next_offset = json_dict_next_page['meta']['next_offset']
					limit = json_dict_next_page['meta']['limit']
					json_dict['meta'] = json_dict_next_page['meta']

		return json_dict

	def _get_id_from_name(self, object_type, id_property, name_property, object_name):
		url = f'{self.base_url}{object_type}'
		response = self._get_json_from_resource(url)
		if 'items' in response:
			items = response['items']
			for item in items:
				if name_property in item:
					if item[name_property] == object_name:
						if id_property in item:
							return item[id_property]	
			
		return -1			

	# Device API calls	
	def get_all_devices(self):
		"""Return all of the devices in the data model
		Returns:
			result (dict): All data associated with a response.
		"""

		url = f'{self.base_url}devices'
		response = self._get_json_from_resource(url)
		return response

	def get_devices_with_custom_attributes(self, custom_attr_name_list):

		url = f'{self.base_url}custom-attribute-values'
		json_dict = self.get_json_from_resource(url)

		device_ids_set = set()
		items = json_dict['items']
		for item in items:
			cust_attr_name = item['attributeDefinition']['name']
			if cust_attr_name in cust_attr_name_list:
				device_ids_set.update(item['deviceIds'])

		return list(device_ids_set)

	def _add_devices_from_json(self, devices_json):
		
		url = f'{self.base_url}devices'

		try:
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			response = self.service.conn.request('POST', url, body=dumps(devices, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
		except (NameError,AttributeError,TypeError) as e:
			logger.debug(f"Attribute error: {e}")
		except:
			logger.debug(f"Exception while getting data from {url}:")

		return response

	def add_device(self, device_name, access_address):

		device = Device(device_name, access_address)

		devices = []
		devices.append(device)
		json_dict = {'items':devices}

		response = self._add_devices_from_json(self, json_dict)

		return response

	def add_devices(self, devices):
		json_dict = {'items':devices}
		
		response = self._add_devices_from_json(self, json_dict)

		return response

	# Interface API calls
	def get_all_device_interfaces(self, device_id):
		url = f'{self.base_url}devices/{device_id}/interfaces'
		device_interfaces_json = self._get_json_from_resource(url)
		return device_interfaces_json

	# Group API calls
	def get_all_groups(self):
		url = f'{self.base_url}groups'
		groups_json = self._get_json_from_resource(url)
		return groups_json

	# Location API calls
	def get_all_countries(self):
		url = f'{self.base_url}countries'
		countries_json = self._get_json_from_resource(url)
		return countries_json
	
	def get_country_by_id(self, country_id):
		url = f'{self.base_url}countries/{id}'
		country_json = self._get_json_from_resource(url)
		return country_json
	
	def get_regions_by_country_id(self, country_id):
		url = f'{self.base_url}countries/{country_id}/regions'
		regions_json = self._get_json_from_resource(url)
		return regions_json
	
	def get_region_by_id(self, region_id):
		url = f'{self.base_url}regions/{region_id}'
		region_json = self._get_json_from_resource(url)
		return region_json
	
	def get_cities_by_region_id(self,region_id):
		url = f'{self.base_url}regions/{region_id}/cities'
		cities_json = self._get_json_from_resource(url)
		return cities_json

	def get_city(self,city_id):
		url=f'{self.base_url}cities/{city_id}'
		cities_json = self._get_json_from_resource(url)
		return cities_json

	# Monitored Path API calls
	def get_all_monitoredpaths(self):
		url = f'{self.base_url}monitored-paths'
		paths_json = self._get_json_from_resource(url)
		return paths_json
	
	# Test API calls
	def get_all_tests(self):
		url = f'{self.base_url}tests'
		tests_json = self._get_json_from_resource(url)
		return tests_json

	# Alert Profile API calls
	def get_all_alert_profiles(self):
		url = f'{self.base_url}alert-profiles'
		profiles_json = self._get_json_from_resource(url)
		return profiles_json

	# Polling Profile API calls
	def get_all_polling_profiles(self):
		url = f'{self.base_url}polling-profiles'
		profiles_json = self._get_json_from_resource(url)
		return profiles_json

	# Custom Attribute API calls
	def get_custom_attributes(self):
		url = f'{self.base_url}custom-attributes'
		response = self._get_json_from_resource(url)
		return response

	def get_custom_attribute_id_by_name(self, name):
		cust_attrs = self.get_custom_attributes()
		items = cust_attrs['items']
		for item in items:
			if item['name'] == name:
				return item['id']
		return -1
	
	def add_custom_attribute(self, name, description, type='string'):
		
		url = f'{self.base_url}custom-attributes'
		cust_attr = CustomAttribute(name, description, type)

		response = None
		try:
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			response = self.service.conn.request('POST', url, body=dumps(cust_attr, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
		except (NameError,AttributeError,TypeError) as e:
			logger.debug(f"Attribute error: {e}")
		except:
			logger.debug(f"Exception while getting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return response

	def import_custom_attribute_values_for_devices(self, device_ids, cust_attr_name, value):

		url = f'{self.base_url}custom-attribute-values'

		attribute_id = self.get_custom_attribute_id_by_name(cust_attr_name)
		cust_attr_value = CustomAttributeValue(device_ids=device_ids, attribute_id=attribute_id, value=value)

		response = None
		try:
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			response = self.service.conn.request('POST', url, body=dumps(cust_attr_value, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
		except:
			logger.debug(f"Exception while getting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return None
		
