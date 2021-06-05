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

__all__ = ['DefinitionJSONEncoder', 'Definition', \
	'CustomAttributeDefinitionCreate', 'NewCustomAttributeValue', 'ModifyCustomAttributeValue', \
	'ModifiableDefaultThreshold', 'ModifiableInterface', \
	'ModifiableAlertProfileBean', 'ModifiablePollingProfileBean', \
	'ModifiableNotificationTemplate', \
	'CreatableGroup', 'ModifiableGroup', 'Group', \
	'ModifiableInterface', \
	'ModifiableLink', 'ModifiableLinkList', \
	'ModifiableDevice', ModifiableDeviceAccessInfoBean', 'ModifiableDeviceList', \
	'Metric', 'NetIM'] 

logging.captureWarnings(True)
logger = logging.getLogger(__name__)

# Helper Class Definitions
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

	def __str__(self):
		output = ''
		class_name = str(self.__class__).split('.')[-1].replace("'>","")
		for attribute, value in self.attributes.items():
			output += f"{class_name} - {attribute}:{value}"
		return output

	def __repr__(self):
		return self.__str__()

# Class Objects for Manipulation of NetIM Configurations

NETIM_OPERATOR_LESS_THAN='LESS_THAN'
NETIM_OPERATOR_EQUAL_TO='EQUAL_TO'
NETIM_OPERATOR_GREATER_THAN='GREATER_THAN'

class ModifiableDefaultThreshold(Definition):

	def __init__(self, name, display_name, id, minor, major, critical, operator):

		self.name = name
		self.displayName = display_name
		self.id = id
		self.minor = minor
		self.major = major
		self.critical = critical
		self.operator = operator

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

class ModifiableNotificationTemplate(Definition):
	def __init__(self, name, id, default, subject, message, links):
		self.name = name
		self.id = id
		self.default = default
		self.subject = subject
		self.message = message
		self.links = links

NETIM_CUSTOM_ATTRIBUTE_TYPE_STRING='STRING'
NETIM_CUSTOM_ATTRIBUTE_TYPE_NUMERIC='NUMERIC'

class ObjectTypeCreateUpdate(Definition):
	def __init__(self, type, promoted):
		self.type = type
		self.promoted = promoted

class CustomAttributeDefinitionCreate(Definition):
	def __init__(self, name, description, type=NETIM_CUSTOM_ATTRIBUTE_TYPE_STRING, object_type_create_update_list=[]):
	# 'type' = STRING or NUMERIC
	# 'object_type' = DEVICE, LINK, GROUP, INTERFACE

		self.name = name
		self.description = description
		self.type = type
		self.objectTypes = []
		for object_type_create_update in object_type_create_update_list:
			self.objectTypes.append(object_type_create_update)

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

class ModifiableDeviceAccessInfoBean(Definition):
	def __init__(self, device_name, access_address, description='', active=True, device_driver='', 
		active_cli=True, active_mib=True, active_wmi=False, active_metric=False, active_aws=False,
		has_cli_password=True, has_cli_privpassword=False,
		cli_username='', cli_loginscript='InitPrompt', cli_accessmethod=3, cli_password=None, cli_privpassword=None,
		snmp_version=1,  snmp_communitystring=None,
		snmpv3_securitylevel=None, snmpv3_username=None, snmpv3_context=None, 
		snmpv3_authprotocol=None, snmpv3_privprotocol=None,
		snmpv3_password=None, snmpv3_privpassword=None, snmpv3_authpassword=None,
		wmi_username="none", wmi_domain="none", wmi_password=None,
		aws_instanceid="none", aws_accesskeyid="none", aws_region="none", aws_secretaccesskey="none",
		extmgmt_srvtype=None, extmgmt_srvid=None, extmgmt_srvdevid=None):

		# cli_accessmethod - 0: Not Set, 1: Telnet, 2: SSHv1, 3: SSHv2
		# cli_snmpversion - 1000: Not Set, 0: v1, 1: v2c, 3: SNMPv3

		# Device details
		self.name = device_name
		self.displayName = device_name
		self.accessAddress = access_address
		self.deviceDriver = device_driver
		self.active = active

		# CLI details
		self.activeCLIConfigCollection = active_cli
		self.cliUsername = cli_username
		self.cliLoginScript = cli_loginscript
		self.cliAccessMethod = cli_accessmethod
		if cli_password != None:
			self.cliPassword = cli_password
		if cli_privpassword != None:
			self.cliPrivPassword = cli_privpassword

		# SNMP details
		self.activeMIBConfigCollection = active_mib
		self.activeMetricsCollection = active_metric
		self.snmpVersion = snmp_version
		if snmp_communitystring != None:
			self.snmpCommunityString = snmp_communitystring

		# SNMPv3 details
		if snmpv3_securitylevel != None:
			self.snmpV3SecurityLevel = snmpv3_securitylevel
		if snmpv3_username != None:
			self.snmpV3Username = snmpv3_username
		if snmpv3_context != None:
			self.snmpV3Context = snmpv3_context
		if snmpv3_authprotocol != None:
			self.snmpV3AuthProtocol = snmpv3_authprotocol
		if snmpv3_privprotocol != None:
			self.snmpV3PrivacyProtocol = snmpv3_privprotocol
		if snmpv3_password != None:
			self.snmpV3Password = snmpv3_password
		if snmpv3_privpassword != None:
			self.snmpV3PrivacyPassword = snmpv3_privpassword
		if snmpv3_authpassword != None:
			self.snmpV3AuthPassword = snmpv3_authpassword

		# WMI details
		self.activeWMIConfigCollection = active_wmi
		self.wmiUsername = wmi_username
		self.wmiDomain = wmi_domain
		if wmi_password != None:
			self.wmiPassword = wmi_password

		# AWS details
		self.activeAWSConfigCollection = active_aws
		self.awsInstanceId = aws_instanceid
		self.awsAccessKeyId = aws_accesskeyid
		self.awsRegion = aws_region
		self.awsSecretAccessKey = aws_secretaccesskey

		# External management server
		if extmgmt_srvtype != None:
			self.extMgmtSrvType = extmgmt_srvtype
		if extmgmt_srvid != None:
			self.extMgmtSrvId = extmgmt_srvid
		if extmgmt_srvdevid != None:
			self.extMgmtSrvDevId = extmgmt_srvdevid

class ModifiableDevice(Definition):
	def __init__(self, name, display_name, device_name, access_address, device_access_info, description='',
		city=None, region_id=None, country_code=None, time_zone=None, time_zone_display_name=None, 
		links=None):

		self.name = name
		self.displayName = display_name
		self.deviceName = device_name
		self.accessAddress = access_address
		self.description = description
		self.deviceAccessInfo = device_access_info

		if city != None:
			self.city = city
		if region_id != None:
			self.region_id = region_id
		if country_code != None:
			self.country_code = country_code
		if time_zone != None:
			self.time_zone = time_zone
		if time_zone_display_name != None:
			self.time_zone_display_name = time_zone_display_name
		if links != None:
			self.links = links

class ModifiableDeviceList(Definition):
	
	def __init__(self, device_list):

		self.items = []

		for device_entry in device_list:
			if 'device_name' not in device_entry or 'access_address' not in device_entry:
				continue

			# Required parameters for each device entry in device list
			device_name = device_entry['device_name']
			access_address = device_entry['access_address']

			# Optional parameters for each device entry in device list
			# Update here and when device access info bean is crecreated to add supported options
			description = "None" if 'description' not in device_entry else device_entry['description']
			device_driver = '' if 'device_driver' not in device_entry else device_entry['device_driver'] 
			cli_username = '' if 'cli_username' not in device_entry else device_entry['cli_username']

			# Create device
			device_access_info = ModifiableDeviceAccessInfoBean(device_name, access_address, 
				description=description, device_driver=device_driver, cli_username=cli_username)
			device = ModifiableDevice(name=device_name, display_name=device_name, device_name=device_name, 
				access_address=access_address, device_access_info=device_access_info)

			self.items.append(device)

		# self.meta = total, count, limit, offset, next_offset, prev_offset

class ModifiableInterface(Definition):
	def __init__(self, if_speed_in, if_speed_out, polling_override):
		self.ifSpeedIn = if_speed_in
		self.ifSpeeOut = if_speed_out
		self.pollingOverride = polling_override

NETIM_LINK_TYPE_PHYSICAL = 'Physical'
NETIM_LINK_TYPE_LOGICAL = 'Logical'

class ModifableEndPointBean(Definition):
	def __init__(self, name, display_name, id, type, child):
		self.name = name
		self.displayName = display_name
		self.id = id
		self.type = type
		self.child = child

class ModifiableLink(Definition):
	def __init__(self, name, display_name, id, link_type=NETIM_LINK_TYPE_PHYSICAL, is_locked=False, endpoints=[], links=None):
		self.name = name
		self.displayName = display_name
		self.id = id
		self.linkType = link_type
		self.isLocked = is_locked
		self.endPoints = endpoints
		self.links = links

class ModifiableLinkList(Definition):

	def __init__(self, links):
		self.items = links

class HealthEnum(Definition):
	def __init__(self, health_value, health_name):
		self.healthValue = health_value
		self.healthName = health_name

class CreatableGroup(Definition):
	def __init__(self, name, description='', add_devices=[], add_groups=[], type='Subnet'):
		self.name = name
		self.description = description
		self.addDevices = add_devices
		self.addGroups = add_groups
		self.type = type # User/Subnet

class ModifiableGroup(Definition):
	def __init__(self, name, description='', add_devices=[], add_groups=[], remove_devices=[], remove_groups=[]):
		self.name = name
		self.description = description
		self.addDevices = add_devices
		self.addGroups = add_groups
		self.removeDevices = remove_devices
		self.removeGroups = remove_groups

class Group(Definition):
	def __init__(self, name, display_name, id, health, interface_health, links, type, description,
		device_count, parent_group_count, subgroup_count, custom_attributes):

		self.name = name
		self.displayName = display_name
		self.id = id
		self.health = health
		self.interfaceHealth = interface_health
		self.links = links
		self.type = type
		self.description = description
		self.deviceCount = device_count
		self.parentGroupCount = parent_group_count
		self.subGroupCount = subgroup_count
		self.customAttributes = custom_attributes

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
	# General Class functions
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
		json_dict = None
		try:
			json_dict = self.service.conn.json_request('GET', url)
			if json_dict == None:
				logger.info(f"Exception while getting data from {url}:")
				raise
		except AttributeError as e:
			logger.info(f"Exception while getting data from {url}:")
			logger.debug(f"Attribute error: {e}")
			raise
		except:
			logger.info(f"Exception while getting data from {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return json_dict

	def _get_json_from_resource_page(self, resource_url, limit, offset):
		if '?' in resource_url:
			next_url_char = '&'
		else:
			next_url_char = '?'
		final_url = resource_url + next_url_char + 'limit=' + str(limit) + '&offset=' + str(offset)
		json_dict = self._get_json(final_url)
		return json_dict

	def _get_json_from_resource(self, resource_url):
		json_dict = self._get_json(resource_url)

		# Handle error in return gracefully so script can continue
		if json_dict == None:
			logger.info(f"No response from {resource_url}")
			raise Exception(f"No response from {resource_url}")

		# If JSON dict is first of a series of paged data, loop through getting additional pages
		if 'meta' in json_dict:
			total = json_dict['meta']['total']
			next_offset = json_dict['meta']['next_offset']
			limit = json_dict['meta']['limit']
			while next_offset < total:
				json_dict_next_page = self._get_json_from_resource_page(resource_url, \
					limit, next_offset) 
				total_items = json_dict['items']
				total_items.extend(json_dict_next_page['items'])
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
			url = f'{self.base_url}{object_type}'
			json_dict = self._get_json_from_resource(url)
		except:
			logger.info("Unable to pull {object_type} resource from NetIM")
			return obj_name_to_id_dict

		try:
			items = json_dict['items']
		except KeyError:
			logger.debug(f"'items' not found in resource {object_type}")
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
	def get_archives_by_device_id(self, device_id, file_filter='ALL', file_type='cfg'):

		archives = []

		url = f'{self.base_url}devices/{device_id}/archives'
		url += f'?fileFilter={file_filter}&fileType={file_type}'
		response = self._get_json_from_resource(url)

		if 'items' in response:
			archives = response['items']
			
		return archives

	def get_archive_by_id(self, archive_id):
		
		url = f'{self.base_url}archives/{archive_id}'
		response = self._get_json_from_resource(url)
		return response

	def get_archive_file_by_id(self, archive_id):

		url = f'{self.base_url}archives/{archive_id}/file'
		extra_headers = {}
		extra_headers['Content-Type'] = 'text/plain'
		extra_headers['Accept'] = 'text/plain'

		response_text = None
		try:
			response = self.service.conn.request('GET', url, extra_headers)
		except:
			logger.info(f"Exception while getting configuration file from {url}")
		if response is not None:
			if response.status_code == 200:
				response_text = response.text
		else:
			raise Exception(f"No response from {url}")
				
		return response_text

	# Default Threshold API calls
	def get_default_thresholds(self):
		url = f'{self.base_url}default-thresholds'
		response = self._get_json_from_resource(url)
		return response

	def get_default_threshold_by_id(self, threshold_id):
		url = f'{self.base_url}default-thresholds/{threshold_id}'
		response = self._get_json_from_resource(url)
		return response

	def update_default_threshold(self, threshold_id, modified_threshold):

		url = f'{self.base_url}default-thresholds/{threshold_id}'
		body = dumps(modified_threshold, cls=DefinitionJSONEncoder)

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		response = None
		try:
			response = self.service.conn.request('PUT', url, body=body, extra_headers=extra_headers)
		except TypeError as e:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug(f"TypeError: {e}")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

		return

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
			if response.status_code == 207:
				logger.info(f"Response from {url} returned in multi-response format.")
				response_json = response.json()
				responses = response_json['responses']
				if 'responses' in response_json:
					for response in responses:
						status=''
						if 'status' in response:
							status = response['status']
						status_info=''
						if 'statusInfo' in response:
							status_info = response['statusInfo']
						logger.info(f"Device status: {status}:{status_info}")
			elif response.status_code >=200 and response.status_code < 300:
				resp_text = response.text
				logger.info(f"Response: {resp_text}")
			else:
				logger.info(f"Error while adding devices. Status code: {response.status_code}")
				logger.debug(f"Check that device names and access addresses do not match existing devices.")
				raise Exception('Error while adding devices')
		else:
			logger.debug(f"Unable to retrieve resource {url}.")
			raise Exception(f'Unable to retrieve data from {url}')

		return response

	def add_device_without_detail(self, device_name, access_address):

		device_id = int(self.get_device_id_by_device_name(device_name))
		if device_id > 0:
			logger.info(f"Device name {device_name} already exists in NetIM.")
			logger.info(f"Delete and re-add device or update relevant device information.")
			raise Exception(f'Device name {device_name} does not exist in NetIM.')

		device_list=[{'device_name':device_name, 'access_address':access_address}]
		devices = ModifiableDeviceList(device_list)
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
			raise
		
		return response

	### def update_device_timezone(self, ...):
	### timeZone, timeZoneDisplayName
	### def update_device_location(self, ...):
	### city, cityDisplayName, regionID, regionIDDisplayName, countryCode, countryCodeDisplayName 
	### def update_device_coordinate(self, ...):
	### longitude, latitude

	# Interface API calls
	def get_all_device_interfaces(self, device_id):
		url = f'{self.base_url}devices/{device_id}/interfaces'
		device_interfaces_json = self._get_json_from_resource(url)
		return device_interfaces_json

	def get_device_interface_name_map(self, url, device_id, use_cache=False):
		url = f'devices/{device_id}/interfaces'
		return self._get_object_id_map(url, 'name', 'id', use_cache)

	### def get_device_interfaces_by_device_id(self, device_id):

	def get_interface(self, interface_id):
		url = f'{self.base_url}interfaces/{interface_id}'
		interface_json = self._get_json_from_resource(url)
		return interface_json

	def delete_interface(self, interface_id):
		url = f'{self.base_url}interfaces/{interface_id}'
		response = None
		try:
			response = self.service.conn.request('DELETE', url, extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add devices to group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add devices to group using {url}. No response from server.")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return

	def update_interface(self, interface_id, modified_interface):
		url = f'{self.base_url}interfaces/{interface_id}'
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		response = None
		try:
			response = self.service.conn.request('PATCH', url, body=dumps(modified_interface, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add devices to group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add devices to group using {url}. No response from server.")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return

	def get_hosts_on_interface(self, interface_id, detected_ips_only=False, including_polling_info=True):
		url = f'{self.base_url}interfaces/{interface_id}/hosts'
		url += f'?detectedIPsOnly={detected_ips_only}&includePollingInfo={include_polling_info}'
		hosts_json = self._get_json_from_resource(url)
		return hosts_json

	def get_agginterfaces_for_interface(self, interface_id):
		url = f'{self.base_url}interfaces/{interface_id}/agg-interfaces'
		agginterfaces_json = self._get_json_from_resource(url)
		return agginterfaces_json

	def get_subinterfaces_for_interface(self, interface_id):
		url = f'{self.base_url}interfaces/{interface_id}/sub-interfaces'
		subinterfaces_json = self._get_json_from_resource(url)
		return subinterfaces_json

	def get_links_for_interface(self, interface_id, inc_physical=True, inc_logical=True):
		url = f'{self.base_url}interfaces/{interface_id}/links'
		url += f'?incPhysical={inc_physical}&incLogical={inc_logical}'
		links_json = self._get_json_from_resource(url)
		return links_json

	def get_custom_attribute_values_for_interface(self, interface_id):
		url = f'{self.base_url}interfaces/{interface_id}/custom-attribute-values'
		cust_attrs_json = self._get_json_from_resource(url)
		return cust_attrs_json

	# Group and Site API calls
	def get_all_groups(self, group_type=None):
		url = f'{self.base_url}groups'
		if group_type == 'Site' or group_type == 'Subnet':
			url += '?type=Site'
		elif group_type == 'Group' or group_type == 'User':
			url += '?type=Group'
		elif group_type == None or type == 'All':
			pass
		else:
			logger.debug(f"Unexpected group type {group_type} specified.")
			raise Exception(f"Unexpected group type {group_type} specified.")

		groups_json = self._get_json_from_resource(url)
		return groups_json
	
	def get_group(self, group_id):
		url = f'{self.base_url}groups/{group_id}'
		group_json = self._get_json_from_resource(url)
		return group_json

	def _get_group_id_map(self, use_cache=False):
		return self._get_object_id_map('groups', 'id', 'name', use_cache)

	def get_group_id_by_group_name(self, group_name, use_cache=False):
		group_map = self._get_group_id_map(use_cache)
		if group_name in group_map:
			return group_map[group_name]
		else:
			return -1

	def get_devices_in_group(self, group_name, include_subgroups=False):

		group_id = int(self.get_group_id_by_group_name(group_name))
		if group_id == -1:
			raise Exception(f"Group {group_name} not found in NetIM")
		
		devices = []
		url = f'{self.base_url}groups/{group_id}/devices'

		if include_subgroups == True:
			url += '?traverseSubGroups=true'

		try:
			devices_json = self._get_json_from_resource(url)
			if 'items' in devices_json:
				devices = devices_json['items']
		except:
			logger.info(f"Unable to retrieve devices from Group ID {group_id}")
			raise

		return devices

	def get_parent_groups_of_group(self, group_id):
		url = f'{self.base_url}groups/{group_id}/parent-groups'
		if type != None:
			url += f'?type={type}'
		parent_groups_json = self._get_json_from_resource(url)
		return parent_groups_json

	def get_subgroups_of_group(self, group_id, type=None):
		url = f'{self.base_url}groups/{group_id}/sub-groups'
		if type != None:
			url += f'?type={type}'
		subgroups_json = self._get_json_from_resource(url)
		return subgroups_json

	def get_links_in_group(self, group_id, inc_physical=True, inc_logical=False):
		url = f'{self.base_url}groups/{group_id}/links'
		url += f'?incPhysical={inc_physical}&incLogical={inc_logical}'
		links_json = self._get_json_from_resource(url)
		return links_json

	def get_custom_attribute_values_of_group(self, group_id):
		url = f'{self.base_url}groups/{group_id}/custom-attribute-values'
		custom_attribute_values_json = self._get_json_from_resource(url)
		return custom_attribute_values_json

	def add_group(self, group_name, group_description="", group_type='Subnet'):

		if group_type not in ['User', 'Subnet']:
			logger.debug(f'Group type {group_type} not provided as expected.')
			logger.debug(f'Please provide group type of User or Subnet')
			return

		url = f'{self.base_url}groups'
		group = CreatableGroup(name=group_name, description=group_description, type=group_type)

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		try:
			response = self.service.conn.request('POST', url, body=dumps(group, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add devices to group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add devices to group using {url}. No response from server.")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return

	def add_devices_to_group(self, group_name, device_ids=[]):

		if len(device_ids) == 0:
			raise Exception(f"No devices are being added to group")

		group_id = int(self.get_group_id_by_group_name(group_name))
		if group_id < 0:
			logger.info(f"Group name '{group_name}' not found in NetIM")
			raise Exception(f"Group name '{group_name}' not found in NetIM")
		
		url = f'{self.base_url}groups/{group_id}'

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		group_update = ModifiableGroup(group_name, add_devices=device_ids)
		try:
			response = self.service.conn.request('PATCH', url, body=dumps(group_update, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add devices to group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add devices to group using {url}. No response from server.")
		except:
			logger.info(f"Exception while adding devices to {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return

	def remove_devices_from_group(self, group_name, device_ids=[]):

		group_id = int(self.get_group_id_by_group_name(group_name))
		if group_id < 0:
			logger.info(f"Group name '{group_name}' not found in NetIM")	
			return

		url = f'{self.base_url}groups/{group_id}'

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		group_update = ModifiableGroup(group_name, remove_devices=device_ids)
		try:
			response = self.service.conn.request('PATCH', url, body=dumps(group_update, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add devices to group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add devices to group using {url}. No response from server.")
		except:
			logger.info(f"Exception while adding devices to {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		
		return

	def add_group_to_hierarchy(self, group_name, parent_group_name):

		group_id = int(self.get_group_id_by_group_name(group_name))
		if group_id < 0:
			logger.info(f"Group name '{group_name}' not found in NetIM")	
			return
		parent_group_id = int(self.get_group_id_by_group_name(parent_group_name))
		if parent_group_id < 0:
			logger.info(f"Gropu name '{parent_group_name}' not found in NetIM")
			return

		url = f'{self.base_url}groups/{parent_group_id}'

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		group_update = ModifiableGroup(parent_group_name, add_groups=[group_id])
		try:
			response = self.service.conn.request('PATCH', url, body=dumps(group_update, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add group to parent group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add group to parent group using {url}. No response from server.")
		except:
			logger.info(f"Exception while adding devices to {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		

	def remove_group_from_hierarchy(self, group_name, parent_group_name):

		group_id = int(self.get_group_id_by_group_name(group_name))
		if group_id < 0:
			logger.info(f"Group name '{group_name}' not found in NetIM")	
			return
		parent_group_id = int(self.get_group_id_by_group_name(parent_group_name))
		if parent_group_id < 0:
			logger.info(f"Gropu name '{parent_group_name}' not found in NetIM")
			return

		url = f'{self.base_url}groups/{parent_group_id}'

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		group_update = ModifiableGroup(parent_group_name, remove_groups=[group_id])
		try:
			response = self.service.conn.request('PATCH', url, body=dumps(group_update, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to remove group from parent group using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to remove group from parent group using {url}. No response from server.")
		except:
			logger.info(f"Exception while adding devices to {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		
		return

	def delete_all_groups(self, group_type):
		
		if group_type not in ['ALL', 'SITE', 'GROUP']:
			return

		url = f'{self.base_url}groups'
		
		final_url = url + '?type=' + group_type + '&confirmDeleteAll=false'

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		try:
			response = self.service.conn.request('DELETE', final_url, extra_headers=extra_headers)
		except:
			logger.info(f"Exception while deleting groups using {final_url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		
		return 

	def delete_group_by_id(self, group_id):
		url = f'{self.base_url}groups/{group_id}'

		response = None
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		try:
			response = self.service.conn.request('DELETE', url, extra_headers=extra_headers)
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		
		return 

	def delete_group(self, group_name):
		group_id = int(self.get_group_id_by_group_name(group_name))
		if group_id >= 0:
			self.delete_group_by_id(group_id)
		else:
			logger.DEBUG(f'Group name {group_name} not found')
		return
		
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
	def get_all_hosts(self, detected_ips_only=False):
		url = f'{self.base_url}hosts'
		hosts_json = self._get_json_from_resource(url)
		return hosts_json

	def get_host_by_id(self, host_id):
		url = f'{self.base_url}hosts/{host_id}'
		host_json = self._get_json_from_resource(url)
		return host_json

	### def get_connected_interface_by_host_id(self, host_id):

	# Links API calls
	def get_custom_attributes_from_link(self, link_id):
		url = f'{self.base_url}links/{link_id}/custom-attribute-values'
		cust_attrs_json = self._get_json_from_resource(url)
		return cust_attrs_json

	def get_all_links(self, inc_physical=True, inc_logical=False):
		url = f'{self.base_url}links'
		url += f'?incPhysical={inc_physical}&incLogical={inc_logical}'
		links_json = self._get_json_from_resource(url)
		return links_json

	def add_links(self, links):
		url = f'{self.base_url}links'
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		response = None
		try:
			response = self.service.conn.request('POST', url, body=dumps(link, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to add links using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to add links using {url}. No response from server.")
		except:
			logger.info(f"Exception while adding data using {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return response

	def delete_all_links(self, links, confirm_delete_all=False):
		url = f'{self.base_url}links'
		url += f'?confirmDeleteAll={confirm_delete_all}'
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		response = None
		try:
			response = self.service.conn.request('DELETE', url, body=dumps(link, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to delete all links using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to delete all links using {url}. No response from server.")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise
		return 

	def get_link_by_id(self, link_id):
		url = f'{self.base_url}links/{link_id}'
		link_json = self._get_json_from_resource(url)
		return link_json

	def delete_link_by_id(self):
		url = f'{self.base_url}links/{link_id}'
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		response = None
		try:
			response = self.service.conn.request('DELETE', url, body=dumps(link, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to delete link using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to delete link using {url}. No response from server.")
		except:
			logger.info(f"Exception while deleting data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise
		return

	def update_link_by_id(self, link_id, modifiable_link):
		url = f'{self.base_url}links/{link_id}'
		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'

		response = None
		try:
			response = self.service.conn.request('PATCH', url, body=dumps(link, cls=DefinitionJSONEncoder),
				extra_headers=extra_headers)
			if response is not None:
				if response.status_code < 200 or response.status_code > 300:
					logger.debug(f"Unable to update link using {url}. " + \
						 "Status code: {response.status_code}")
			else:
				logger.debug(f"Unable to update link using {url}. No response from server.")
		except:
			logger.info(f"Exception while updating data from {url}")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise
		return

	# Metric Classes API calls
	def get_all_metric_classes(self):
		url = f'{self.base_url}metric-classes'
		response = self._get_json_from_resource(url)
		return response

	def get_metric_class_from_id(self, metric_class_id):
		url = f'{self.base_url}metric-classes/{metric_class_id}'
		response = self._get_json_from_resource(url)
		return response

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
			raise Exception(f"Custom Attribute '{name}' not found in NetIM")
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

		return response

	def update_custom_attribute_value(self, cust_attr_name, old_value, new_value):
		attribute_id = int(self.get_custom_attribute_value_id_by_name_and_value(cust_attr_name, old_value))
		if attribute_id >= 0:
			url = f'{self.base_url}custom-attribute-values/{attribute_id}'
		else:
			raise Exception(f"Custom attribute '{cust_attr_name}' not found in NetIM.")

		extra_headers = {}
		extra_headers['Content-Type'] = 'application/json'
		extra_headers['Accept'] = 'application/json'
		body = {}
		body['value'] = new_value

		try:
			response = self.service.conn.request('PUT', url, body=dumps(body), extra_headers=extra_headers)
			if response.status_code >=200 and response.status_code < 300:
				resp_text = response.text
				logger.info(f"Response: {resp_text}")
			else:
				logger.info(f"Error while updating custom attribute value. Status code: {response.status_code}")
				raise Exception(f"Error in response to {url}: {response}")
		except RvbdHTTPException as e:
			logger.debug(f"RvbdHTTPException: {e}")
			raise
		except AttributeError as e:
			logger.debug(f"AttributeError: {e}")
			raise
		except NameError as e:
			logger.debug(f"NameError: {e}")
			raise
		except:
			logger.info(f"Exception while putting data to {url}:")
			logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
			raise

		return

	def reset_custom_attribute_name_and_value(self, name, description, value, 
		device_ids=[], interface_ids=[], link_ids=[], group_ids=[], test_ids=[]):

		# Delete existing Custom Attribute
		try:
			self.delete_custom_attribute(name)
		except:
			attribute_id = int(self.get_attribute_id_by_name(name))
			if attribute_id >= 0:
				raise Exception(f"Custom Attribute '{name}' deletion failed")
			
		# Add Custom Attribute with appropriate types
		try:
			types = []
			if len(device_ids) > 0:
				types.append('DEVICE')
			if len(interface_ids) > 0:
				types.append('INTERFACE')
			if len(link_ids) > 0:
				types.append('LINK')
			if len(group_ids) > 0:
				types.append('GROUP')
			if len(test_ids) > 0:
				types.append('TEST')
			self.add_custom_attribute(name, description, types)
		except:
			logger.info(f"Exception while adding Custom Attribute")
			raise

		# Add Custom Attribute Values
		try:
			self.add_custom_attribute_values(name, value, device_ids=device_ids, interface_ids=interface_ids,
				link_ids=link_ids, group_ids=group_ids, test_ids=test_ids)
		except:
			logger.info(f"Exception while adding Custom Attribute Values")
			raise

		return

	# Notification Template API calls
	def get_notification_templates(self, include_only_attrs=None, exclude_only_attrs=None):
		url = f'{self.base_url}notification-templates'
		url += f'?notificationTemplateIncludeOnlyAttrs={include_only_attrs}&notificationTemplateExcludeOnlyAttrs={exclude_only_attrs}'
		notification_templates_json = self._get_json_from_resource(url)
		return notification_templates_json
	
	def get_notifcation_template_from_id(self, notification_template_id, include_only_attrs=None, exclude_only_attrs=None):
		url = f'{self.base_url}notification-templates/{notification_template_id}'
		url += f'?notificationTemplateIncludeOnlyAttrs={include_only_attrs}&notificationTemplateExcludeOnlyAttrs={exclude_only_attrs}'
		notification_template_json = self._get_json_from_resource(url)
		return notification_template_json

	### def update_notification_template_from_id(self, notification_template_id, modify_notification_template):
	### def delete_notification_template_from_id(self, notification_template_id):
	### def add_notification_template(self, notification_template):	


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
		
