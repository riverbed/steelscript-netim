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
from steelscript.common.exceptions import RvbdHTTPException

__all__ = ['CustomAttributeDefinitionCreate', 'Devices', 'ModifiableAlertProfileBean', 'ModifiablePollingProfileBean', \
	'Metric', 'NetIM', 'NewCustomAttributeValue']

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

class ObjectTypeCreateUpdate(Definition):

	def __init__(self, type, promoted):
		self.type = type
		self.promoted = promoted

NETIM_TYPE_STRING='STRING'
NETIM_TYPE_NUMERIC='NUMERIC'

class CustomAttributeDefinitionCreate(Definition):

	def __init__(self, name, description, type=NETIM_TYPE_STRING, object_type_create_update_list=[]):
	# 'type' = STRING or NUMERIC
	# 'object_type' = DEVICE, LINK, GROUP, INTERFACE

		self.name = name
		self.description = description
		self.type = type
		self.objectTypes = []
		for object_type_create_update in object_type_create_update_list:
			self.objectTypes.append(object_type_create_update)

class ModifiableAlertProfileBean(Definition):

	def __init__(self, profile_name, display_name, id, description, apply_to_all=False,
		add_access_info_ids=None, remove_access_info_ids=None, alert_thresholds=None,
		schedule=None, notifications=None, is_health_profile=None, group_ids=None, test_ids=None,
		filter_if_types=None, filter_expressions=None, active=False, links=None):

		self.name = profile_name
		self.displayName = display_name
		self.id = id
		self.description = description
		self.applyToAllDevices = apply_to_all
		self.addDeviceAccessInfoIds = add_access_info_ids
		self.removeDeviceAccessInfoIds = remove_access_info_ids
		self.alertThresholds = alert_thresholds
		self.schedule = schedule
		self.notifications = notifications
		self.isHealthProfile = is_health_profile
		self.groupIds = group_ids
		self.testIds = test_ids
		self.filterIfTypes = filter_if_types
		self.filterExpressions = filter_expressions
		self.active = active
		self.links = links

class ModifiablePollingProfileBean(Definition):
	def __init__(self, profile_name, display_name, id, description, apply_to_all=False, 
		add_access_info_ids=None, remove_access_info_ids=None, active=False, default=False, 
		links=None):

		self.name = profile_name
		self.displayName = display_name
		self.id = id
		self.description = description
		self.applyToAllDevices = apply_to_all
		self.addDeviceAccessInfoIds = add_access_info_ids
		self.removeDeviceAccessInfoIds = remove_access_info_ids
		self.active = active
		self.default = default
		self.links = links

class NewCustomAttributeValue(Definition):

	def __init__(self, device_ids = None, interface_ids = None, link_ids = None, group_ids = None, test_ids = None, 
		attribute_id = 0, value = ""):

		self.deviceIds = [] if device_ids is None else device_ids
		self.interfaceIds = [] if interface_ids is None else interface_ids
		self.linkIds = [] if link_ids is None else link_ids
		self.groupIds = [] if group_ids is None else group_ids
		self.testIds = [] if test_ids is None else test_ids
		self.attributeId = attribute_id
		self.value = value

class Devices(Definition):
	
	def __init__(self, device_list):

		self.items = []

		for device_entry in device_list:
			if 'device_name' not in device_entry or 'access_address' not in device_entry:
				continue

			device_name = device_entry['device_name']
			access_address = device_entry['access_address']

			item = {}
			item['name'] = device_name
			item['displayName'] = device_name
			item['deviceName'] = device_name
			item['accessAddress'] = access_address
			item['description'] = "None" if 'description' not in device_entry else device_entry['description']
			deviceAccessInfo = {}
			deviceAccessInfo["name"] = device_name
			deviceAccessInfo["displayName"] = device_name
			deviceAccessInfo["active"] = True if 'active' not in device_entry else device_entry['active']
			deviceAccessInfo["activeCLIConfigCollection"] = True
			deviceAccessInfo["activeMIBConfigCollection"] = True
			deviceAccessInfo["activeWMIConfigCollection"] = False
			deviceAccessInfo["activeMetricsCollection"] = False
			deviceAccessInfo["activeAWSConfigCollection"] = False
			deviceAccessInfo["deviceDriver"] = '' if 'device_driver' not in device_entry else device_entry['device_driver']
			deviceAccessInfo["accessAddress"] = access_address
			deviceAccessInfo["cliUsername"] = '' if 'cli_username' not in device_entry else device_entry['cli_username']
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
			item["deviceAccessInfo"] = deviceAccessInfo

		self.items.append(item)

class Metric(Definition):

	def __init__(self, name, display_name, meta, id, description, units, index, alertable, name_ext,
		value_enum_map, component_part):

		self.name = name
		self.displayName = display_name
		self.meta = meta
		self.id = id
		self.description = description
		self.units = units
		self.alertable = alertable
		self.nameExt = name_ext
		self.valueEnumMap = value_enum_map
		self.componentPart = component_part

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
			enable_auth_detection=False,
			supports_auth_basic=True,
			supports_auth_cookie=False,
			supports_auth_oauth=False,
			enable_services_version_detection=False)

		if version is None:
			self.version = 'v1'
		else:
			self.version = version
		
		self.base_url = f'/api/netim/{self.version}/'
		self.map_cache = {}
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
				logger.info(f"Exception while getting data from {url}:")
				return None
		except AttributeError as e:
			logger.info(f"Exception while getting data from {url}:")
			logger.debug(f"Attribute error: {e}")
			return None
		except:
			logger.info(f"Exception while getting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			return None

		return json_dict

	def _get_json_from_resource_page(self, resource_url, limit, offset, verify_ssl=False):
		### use verify_ssl
		final_url = resource_url + '?limit=' + str(limit) + '&offset=' + str(offset)
		json_dict = self._get_json(final_url)
		return json_dict

	def _get_json_from_resource(self, resource_url, verify_ssl=False):
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
				json_dict_next_page = self._get_json_from_resource_page(resource_url, \
					limit, next_offset, verify_ssl) 
				total_items = json_dict['items']
				total_items.update(json_dict_next_page['items'])
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

	def _get_object_id_map(self, object_type, id_property_name, name_attr=None, name_attr_alias=None, use_cache=False):
		
		obj_name_to_id_dict = {}
		if object_type == None or name_attr == None:
			return obj_name_to_id_dict

		map_cache_key = object_type + '_' + id_property_name + '_' + name_attr
		if use_cache == True and map_cache_key in self.map_cache:
			return self.map_cache[map_cache_key]

		try:
			json_dict = self._get_json_from_resource(self, object_type)
		except:
			logger.info("Unable to pull {object_type} resource from NetIM")
			return obj_name_to_id_dict

		try:
			items = json_dict['items']
		except KeyError:
			logger.debug(f"'items\' not found in resource {object_type}")
			return obj_name_to_id_dict

		for item in items:
			try:
				netim_object_name = item[name_attr]
			except:
				if name_attr_alias != None:
					netim_object_name = item[name_attr_alias]

			object_id = item[id_property_name]
			obj_name_to_id_dict[netim_object_name] = object_id

		if use_cache == True:
			self.map_cache[map_cache_key] = obj_name_to_id_dict

		return obj_name_to_id_dict

	# Archive API calls
	###def get_archives_by_device_id(self, device_id):
	###def get_archive_by_id(self, archive_id):
	###def get_archive_file_by_id(self, archive_id):

	# Device API calls	
	def get_device_id_by_device_name(self, device_name):
		devices = self.get_all_devices()

		items = []
		if 'items' in devices:
			items = devices['items']

		for item in items:
			if item['deviceName'] == device_name:
				return item['id']

		logger.debug(f"Unable to find device {device_name}")
		return -1

	def get_all_devices(self):
		"""Return all of the devices in the data model
		Returns:
			result (dict): All data associated with a response.
		"""

		url = f'{self.base_url}devices'
		response = self._get_json_from_resource(url)
		return response

	def get_devices_by_vendor(self, vendor_list):
		url = f'{self.base_url}devices'
		json_dict = self._get_json_from_resource(url)

		devices = []
		vendors = [vendor.lower() for vendor in vendor_list]
		items = json_dict['items']

		for item in items:
			try:
				device_vendor = item['vendor']
				if device_vendor.lower() in vendors:
					try:
						device_ip = item['accessAddress']
					except:
						device_ip = ""
					try:
						device_name = item['sysName']
					except:
						device_name = item['deviceName']
					device_tuple = (device_name,device_ip,device_vendor)
					devices.append(device_tuple)
			except:
				device_vendor = ""

		return devices

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

	def _get_sysname_access_id_map(self, use_cache=False):
		return self._get_object_id_map('devices', 'id', 'sysName', 'deviceName', use_cache)

	def _get_device_access_id_map(self, use_cache=False):
		return self._get_object_id_map('devices', 'deviceAccessInfoId', 'sysName', 'deviceName', use_cache)	

	def _add_devices_from_definition(self, devices):
		url = f'{self.base_url}devices'
		response = None
		try:
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			body = dumps(devices, cls=DefinitionJSONEncoder)
			response = self.service.conn.request('POST', url, body=body, extra_headers=extra_headers)
		except (NameError,AttributeError,TypeError) as e:
			logger.info(f"Exception while posting to URL: {url}")
			logger.debug(f"Attribute error: {e}")
		except:
			logger.info(f"Exception while posting data to {url}")

		if response is not None:
			if response.status_code >=200 and response.status_code < 300:
				resp_text = response.text
				logger.info(f"Response: {resp_text}")
			else:
				logger.info(f"Error while adding devices. Status code: {response.status_code}")
				logger.debug(f"Check that device names and access addresses do not match existing devices.")
		else:
			logger.debug(f"Unable to retrieve resource {url}.")

		return response

	def add_device_without_detail(self, device_name, access_address):

		device_list=[{'device_name':device_name, 'access_address':access_address}]
		devices = Devices(device_list)
		response = self._add_devices_from_definition(devices)

		return response

	def add_devices(self, devices):
		response = self._add_devices_from_definition(devices)
		return response

	def delete_device(self, device_name):
		device_id = int(self.get_device_id_by_device_name(device_name))
		if device_id >= 0:
			self.delete_device_by_id(device_id)
		else:
			logger.DEBUG(f'Device name {device_name} not found')
		return

	def delete_device_by_id(self, device_id, exclude=False):
		url = f'{self.base_url}devices/{device_id}'
		parameters = f'id={device_id}&excludeFromDiscovery={exclude}'
		response = None
		try:
			response = self.service.conn.request('DELETE', url + '?' + parameters)
		except TypeError as e:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug(f"TypeError: {e}")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return response

	def delete_devices_by_id(self, device_id_list):
		url = f'{self.base_url}devices'
		data = {'objectIds': device_id_list}

		parameters = 'excludeFromDiscovery=false&confirmDeleteAll=true'
		response = None
		try:
			response = self.service.conn.request('DELETE', url + '?' + parameters, 
				data=dumps(data))
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		
		return response

	# def update_device_timezone(self, ...):
	# timeZone, timeZoneDisplayName
	# def update_device_location(self, ...):
	# city, cityDisplayName, regionID, regionIDDisplayName, countryCode, countryCodeDisplayName 
	# def update_device_coordinate(self, ...):
	# longitude, latitude

	# Interface API calls
	def get_all_device_interfaces(self, device_id):
		url = f'{self.base_url}devices/{device_id}/interfaces'
		device_interfaces_json = self._get_json_from_resource(url)
		return device_interfaces_json

	def get_device_interface_name_map(self, url, device_id, use_cache=False):
		url = f'devices/{device_id}/interfaces'
		return self._get_object_id_map(url, 'name', 'id', use_cache)

	###def get_device_interfaces_by_device_id(self, device_id):

	# Group and Site API calls
	def get_all_groups(self, group_type=None):
		url = f'{self.base_url}groups'
		if group_type == 'SITE':
			url += '?type=Site'
		elif group_type == 'GROUP':
			url += '?type=Group'
		elif group_type == None or type == 'ALL':
			pass
		else:
			logger.debug(f"Unexpected group type {group_type} specified.")
			return None
		groups_json = self._get_json_from_resource(url)
		return groups_json
	
	def _get_group_id_map(self, use_cache=False):
		return self._get_object_id_map('groups', 'id', 'name', use_cache)

	#def get_group_id_by_group_name(self, group_name):
	#def get_parent_groups_of_group(self, group_id):
	#def get_sub_groups_of_group(self, group_id):
	#def get_devices_in_group(self, group_id):
	#def get_links_in_group(self, group_id):
	#def get_custom_attribute_values_of_group(self, group_id):

	def add_group_and_members(self, group_name, group_description="", group_type='ALL', add_groups = [], device_ids = []):
		if group_type not in ['ALL', 'SITE', 'GROUP']:
			logger.debug(f'Group type {group_type} not provided as expected.')
			logger.debug(f'Please provide group type of ALL, SITE, or GROUP')
			return

		url = f'{self.base_url}groups'
		body_json = {
			'name': group_name,
			'description': group_description,
			'type': group_type,
			'addDevices': device_ids,
			'addGroups': add_groups
			}
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		try:
			response = self.service.conn.request('POST', url, body=dumps(body_json),
				extra_headers=extra_headers)
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return

	#def delete_group_by_id(self, group_id):
	#def delete_group(self, group_name):
	#def update_group_membership(self, add_group_ids, add_devices, remove_group_ids, remove_devices):
	#def delete_all_groups(self, group_type):
	

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

	# Host API calls
	###def get_all_hosts(self):
	###def get_host_by_id(self, host_id):
	###def get_connected_interface_by_host_id(self, host_id):

	# Links API calls
	###def get_all_links(self):
	###def get_link_by_id(self):
	###def delete_link_by_id(self):
	###def patch_link_by_id(self):
	###def add_link(self, link_info):
	###def delete_link_by_id(self, link_id):
	###def patch_link(self, link_id, link_info):

	# Metric Classes API calls
	###def get_metric_classes(self):
	###def get_metric_class_by_id(self, metric_class_id):

	# Monitored Path API calls
	def get_all_monitoredpaths(self):
		url = f'{self.base_url}monitored-paths'
		paths_json = self._get_json_from_resource(url)
		return paths_json

	def _get_anp_id_map(self, use_cache=False):
		return self._get_object_id_map('monitored-paths', 'id', 'name', use_cache)
	
	# Test API calls
	def get_all_tests(self):
		url = f'{self.base_url}tests'
		tests_json = self._get_json_from_resource(url)
		return tests_json

	def _get_test_id_map(self, use_cache=False):
		return self._get_object_id_map('tests', 'id', 'name', use_cache)

	# Alert Profile API calls
	def get_all_alert_profiles(self):
		url = f'{self.base_url}alert-profiles'
		profiles_json = self._get_json_from_resource(url)
		return profiles_json

	def add_devices_to_alert_profiles(self, profile_sysname_map, use_cache=False):
		self._patch_profiles('alert-profiles', 'addDeviceAccessInfoIds', profile_sysname_map, use_cache)
		return
		
	def remove_devices_from_alert_profiles(self, profile_sysname_map, use_cache=False):
		self._patch_profiles('alert-profiles', 'removeDeviceAccessInfoIds', profile_sysname_map, use_cache) 
		return

	def _get_alert_profile_id_map(self, use_cache=False):
		return self._get_object_id_map('alert-profiles', 'id', 'name', use_cache)

	# Polling Profile API calls
	def get_all_polling_profiles(self):
		url = f'{self.base_url}polling-profiles'
		profiles_json = self._get_json_from_resource(url)
		return profiles_json

	def add_devices_to_polling_profiles(self, profile_sysname_map, use_cache=False):
		self._patch_profiles('polling-profiles', 'addDeviceAccessInfoIds', profile_sysname_map, use_cache)
		return

	def remove_devices_from_polling_profiles(self, profile_sysname_map, use_cache=False):
		self._patch_profiles('polling-profiles', 'removeDevicesAccessInfoIds', profile_sysname_map, use_cache)
		return

	def _patch_profiles(self, object_type, operation, profile_sysname_input, use_cache=False):
		# Get device to ID mapping
		sysname_to_access_id_map = self._get_device_access_id_map(use_cache)

		# Get list of profiles
		url = f'{self.base_url}{object_type}'
		json_dict = self._get_json_from_resource(url)
		items = json_dict['items']

		# For each profile, find if the profile is specified in the input
		for item in items:
			profile_name = item['name']
			if profile_name not in profile_sysname_map:
				continue
	
			device_sysnames = profile_sysname_input[profile_name]
			device_access_info_ids = []
			for device_sysname in device_sysnames:
				try:
					device_access_info_id = sysname_to_access_id_map[device_sysname]
					device_access_info_ids.append(device_access_info_id)
				except:
					continue
			if len(device_access_info_ids) == 0:
				continue

			if operation == 'addDeviceAccessInfoIds':
				add_access_info_ids = device_access_info_ids
				remove_access_info_ids = []
			else:
				add_access_info_ids = []
				remove_access_info_ids = device_access_info_ids

			profile_id = str(item['id'])
			if object_type == 'polling-profiles':
				profile_to_set = ModifiablePollingProfileBean(profile_name, 
						item['displayName'], 
						profile_id, 
						item['description'],
						add_access_info_ids=add_access_info_ids,
						remove_access_info_ids=remove_access_info_ids,
						apply_to_all=item['applyToAllDevices'],
						active=item['active'],
						default=item['default'],
						links=item['links']
						)
			elif object_type == 'alert-profiles':
				profile_to_set = ModifiableAlertProfileBean(profile_name,
					item['displayName'], 
					profile_id, 
					item['description'],
					add_access_info_ids=add_access_info_ids,
					remove_access_info_ids=remove_access_info_ids,
					apply_to_all=item['applyToAllDevices'],
					alert_thresholds=item['alertThresholds'],
					schedule=item['schedule'],
					notifications=item['notifications'],
					is_health_profile=item['isHealthProfile'],
					group_ids=item['groupIds'],
					test_ids=item['testIds'],
					filter_if_types=items['filterIfTypes'],
					filter_expressions=items['filterExpressions'],
					active=item['active'],
					default=item['default'],
					links=item['links'])

			profile_url = f'{url}/{profile_id}'

			try:
				response = self.service.conn.request('PATCH', profile_url, 
					data=dumps(profile_to_set, cls=DefinitionJSONEncoder))
				if response is not None:
					if response.status_code < 200 or response.status_code > 300:
						logger.debug(f"Unable to patch profile {profile_url}. " + \
							 "Status code: {response.status_code}")
				else:
					logger.debug(f"Unable to patch profile {profile_url}. No response from server.")
			except:
				logger.info("Exception in patch of {profile_url}.")
				logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return

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

		logger.debug(f"Unable to find custom attribute {name}")
		return -1
	
	def add_custom_attribute(self, name, description, types=['DEVICE'], promoted=True):
		
		url = f'{self.base_url}custom-attributes'
		object_type_create_updates = []
		for type in types:
			object_type_create_update = ObjectTypeCreateUpdate(type, promoted)
			object_type_create_updates.append(object_type_create_update)
		cust_attr = CustomAttributeDefinitionCreate(name, description, 
			object_type_create_update_list=object_type_create_updates)

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
			logger.info(f"Exception while posting data to {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return response

	def delete_custom_attribute(self, name):

		attribute_id = int(self.get_custom_attribute_id_by_name(name))
		if attribute_id < 0:
			logger.info(f"Custom attribute {name} not found")
			return
		url = f'{self.base_url}custom-attributes/{attribute_id}'

		response = None
		try: 
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			response = self.service.conn.request('DELETE', url, extra_headers=extra_headers)
		except:
			logger.info(f"Exception while deleting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	
		return

	def get_custom_attribute_values(self):
		url = f'{self.base_url}custom-attribute-values'
		response = self._get_json_from_resource(url)
		return response

	def get_custom_attribute_value_id_by_name_and_value(self, cust_attr_name, cust_attr_value):
		cust_attr_values = self.get_custom_attribute_values()
		if 'items' in cust_attr_values:
			items = cust_attr_values['items']
			for item in items:
				if ('attributeDefinition' in item and 'name' in item['attributeDefinition'] 
					and item['attributeDefinition']['name'] == cust_attr_name) and ('value' in item
					and item['value'] == cust_attr_value):
					return item['id']
		else:
			logger.info(f"Unable to get custom attribute values")
		
		logger.debug(f"Unable to find custom attribute name '{cust_attr_name}' and value '{cust_attr_value}'")
		return -1

	def add_custom_attribute_values(self, cust_attr_name, value, 
		device_ids=None, link_ids=None, group_ids=None, interface_ids=None, test_ids=None):

		if device_ids == None and link_ids == None and group_ids == None and interface_ids == None and test_ids == None:
			logger.debug("There are no objects specified on which to add custom attribute values")
			return

		url = f'{self.base_url}custom-attribute-values'

		attribute_id = self.get_custom_attribute_id_by_name(cust_attr_name)
		new_cust_attr_value = NewCustomAttributeValue(device_ids=device_ids, link_ids=link_ids,
			group_ids=group_ids, interface_ids=interface_ids, test_ids=test_ids, attribute_id=attribute_id, value=value)

		try:
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			response = self.service.conn.request('POST', url, body=dumps(new_cust_attr_value, 
				cls=DefinitionJSONEncoder), extra_headers=extra_headers)
		except:
			logger.debug(f"Exception while getting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return

	def update_custom_attribute_value(self, cust_attr_name, old_value, new_value):

		attribute_id = int(self.get_custom_attribute_value_id_by_name_and_value(cust_attr_name, old_value))
		if attribute_id >= 0:
			url = f'{self.base_url}custom-attribute-values/{attribute_id}'
		else:
			return

		try:
			extra_headers = {}
			extra_headers['Content-Type'] = 'application/json'
			extra_headers['Accept'] = 'application/json'
			body = {}
			body['value'] = new_value
			response = self.service.conn.request('PUT', url, body=dumps(body),
				extra_headers=extra_headers)
		except RvbdHTTPException as e:
			logger.debug(f"RvbdHTTPException: {e}")
		except AttributeError as e:
			logger.debug(f"AttributeError: {e}")
		except NameError as e:
			logger.debug(f"NameError: {e}")
		except:
			logger.debug(f"Exception while putting data to {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return


	# Notification Template API calls
	def get_notification_templates(self):
		### Include options for notificationTemplateIncludeOnlyAttrs, notificationTemplateExcludeOnlyAttrs
		url = f'{self.base_url}notification-templates'
		response = self._get_json_from_resource(url)
		return response

	# Metric API calls

	#NETIM_METRIC_CLASS_TO_METRIC = {
	#	"DEV_ALERT_EVENTS_DETAIL" : ["ProfileId", "AdditionalData", "AlertId", "AlertSeverity", "Data", "NumTimesSeen", "AlertState"],
	#	"IFC_ALERT_EVENTS_DETAIL" : ["ProfileId", "AdditionalData", "AlertId", "AlertSeverity", "Data", "NumTimesSeen", "AlertState"],
	#	"DEV_SYSLOG_EVENTS_DETAIL" : ["Agent","Severity","Data","AdditionalData"],
	#	"DEV_TRAP_EVENTS_DETAIL" : ["Agent","TrapOID","Category","Severity","TrapDisplayName","Data","AdditionalData"],
	#	"IFC_SYSLOG_EVENTS_DETAIL" : ["Agent","Severity","Data","AdditionalData"],
	#	"IFC_TRAP_EVENTS_DETAIL" : ["Agent","TrapOID","Category","Severity","TrapDisplayName","Data","AdditionalData"]
	#}

	#def get_metric_data(self, metric_class_to_devices_map, obj_name_id_dict, device_interface_id_name_map,
	#	alert_profile_id_map, metric_class_to_metric_map=NETIM_METRIC_CLASS_TO_METRIC):
	#
	#	return json_dict

	#def get_metric_data_for_device(self, ...)
	#def get_top_n_metrics(self, ...)

	# Alert Data API calls
	#def get_alert_data_for_device(self, use_cache=False):
	#	url = f'{self.base_url}'
	#
	#	sysname_device_id_map = self._get_sysname_device_id_map(use_cache)
	#	device_interface_id_name_map = {}
	#	alert_profile_id_map = self._get_alert_profile_id_map(use_cache)

	#	self.get_metric_data(metric_class_to_devices_map, metric_class_to_metric_map,
	#		sysname_device_id_map, device_interface_id_name_map, alert_profile_id_map)

	#	return

	#def get_alert_data_for_anp(self, ...):
	#def get_alert_data_for_group(self, ...):
	#def get_alert_data_for_network(self, ...):
	#def get_alert_data_for_test(self, ...):
		
