import steelscript
from steelscript.common.service import UserAuth, Auth
from steelscript.common.exceptions import RvbdHTTPException
from steelscript.netim.core import NetIM

import argparse
import getpass
import logging
import sys
import time

logging.captureWarnings(True)
logger = logging.getLogger(__name__)

# Uncomment one of the following lines to review logging details interactively
#logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

TEST_WAIT = 2
TEST_AUTOMATION = True

TEST_CUSTOM_ATTRIBUTE = 'Test Custom Attribute'
TEST_CUSTOM_ATTRIBUTE_DESCRIPTION = 'Test attribute created on device'
TEST_CUSTOM_ATTRIBUTE_VALUE = 'Test'
TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED = 'Changed'

TEST_DEVICE_NAME = 'test_appresponse'
TEST_DEVICE_ADDRESS = '10.1.150.220'

TEST_GROUP_NAME = 'groupxyz'
TEST_SITE_NAME = 'Arlington'
TEST_CITY_NAME = 'Arlington'
TEST_REGION_NAME = 'Virginia'
TEST_COUNTRY_NAME = 'United States of America'

TEST_ARCHIVE_DEVICE = 'MidA-Mgt-Switch01'

TEST_POLLED_DEVICE_ID = 15027

def prompt(step1, step2=""):
	print(step1)
	if step2 != "":
		print(step2)
	if TEST_AUTOMATION == False:
		input("Press <Enter> to test the associated APIs.")
	return

def check(success, check=""):
	if success == True:
		print("Success")
		print("")
	else:
		print("Failure")
		print("")
		raise Exception('Test failed')

	if TEST_AUTOMATION == False:
		if check != "":
			print(check)
		input("Press <Enter> when check is complete.")

	return

def test_custom_attributes_apis(netim, test_device_id, test_group_id):

	prompt(f"Adding Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}' to NetIM")
	attribute_id = netim.get_custom_attribute_id_by_name(TEST_CUSTOM_ATTRIBUTE)
	if int(attribute_id) < 0:
		response = netim.add_custom_attribute(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_DESCRIPTION)
		if response == None:
			logger.debug("Failed to create Custom Attribute in NetIM")

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	prompt(f"Checking that Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}' exists on NetIM.")
	try:
		attribute_id = netim.get_custom_attribute_id_by_name(TEST_CUSTOM_ATTRIBUTE)
	except:
		logger.debug("Exception when checking Custom Attribute exists on NetIM")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise
	check(bool(int(attribute_id) >= 0))

	prompt(f"Adding Custom Attribute Values to Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}'")
	try:
		response = netim.add_custom_attribute_values(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_VALUE, 
			device_ids=[test_device_id])
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
		raise
	except NameError as e:
		logger.debug(f"NameError: {e}")
		raise
	except:
		logger.info(f"Exception when importing Custom Attribute Values for device '{device_id}'")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	prompt(f"Checking that Custom Attribute Value '{TEST_CUSTOM_ATTRIBUTE_VALUE}' is set on NetIM.")
	cust_attr_value_id = -1
	try:
		cust_attr_value_id = netim.get_custom_attribute_value_id_by_name_and_value(TEST_CUSTOM_ATTRIBUTE, 
			TEST_CUSTOM_ATTRIBUTE_VALUE)
	except:
		logger.info("Exception when checking Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise
	check(bool(int(cust_attr_value_id) >= 0))

	values = netim.get_custom_attribute_values_for_device_by_attribute_name(test_device_id, TEST_CUSTOM_ATTRIBUTE)

	prompt(f"Changing Custom Attribute Value in Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}'")
	try:
		response = netim.update_custom_attribute_value(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_VALUE,
			TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED)
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
		raise
	except NameError as e:
		logger.debug(f"NameError: {e}")
		raise
	except:
		logger.debug("Exception when importing Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	prompt(f"Checking that Custom Attribute Value '{TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED}' is set on NetIM.")
	cust_attr_value_id = -1
	try:
		cust_attr_value_id = netim.get_custom_attribute_value_id_by_name_and_value(TEST_CUSTOM_ATTRIBUTE, 
			TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED)
	except:
		logger.info("Exception when checking Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise
	check(bool(int(cust_attr_value_id) >= 0))

	prompt(f"Resetting Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}' with Value '{TEST_CUSTOM_ATTRIBUTE_VALUE}'")
	try:
		response = netim.reset_custom_attribute_name_and_value(TEST_CUSTOM_ATTRIBUTE, 
			TEST_CUSTOM_ATTRIBUTE_DESCRIPTION, TEST_CUSTOM_ATTRIBUTE_VALUE, device_ids=[test_device_id], 
			group_ids=[test_group_id])
	except:
		logger.info("Exception when resetting Custom Attribute name and Value")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise
	
	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	prompt(f"Checking that Custom Attribute Value '{TEST_CUSTOM_ATTRIBUTE_VALUE}' is set on NetIM.")
	cust_attr_value_id = -1
	try:
		cust_attr_value_id = netim.get_custom_attribute_value_id_by_name_and_value(TEST_CUSTOM_ATTRIBUTE, 
			TEST_CUSTOM_ATTRIBUTE_VALUE)
	except:
		logger.info("Exception when checking Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise
	check(bool(int(cust_attr_value_id) >= 0))

	prompt(f"Deleting Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}'")
	try:
		response = netim.delete_custom_attribute(TEST_CUSTOM_ATTRIBUTE)
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
		raise
	except NameError as e:
		logger.debug(f"NameError: {e}")
		raise
	except:
		logger.info("Exception when deleting Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	prompt(f"Checking that Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}' has been deleted.")
	attribute_id = -1
	try:
		attribute_id = netim.get_custom_attribute_id_by_name(TEST_CUSTOM_ATTRIBUTE)
	except:
		logger.info("Exception when checking Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise
	check(bool(attribute_id == -1))

	return	

def test_devices_and_groups_apis(netim, netim_devices):

	# ADD DEVICE AND CONFIRM
	prompt(f"Adding test Device '{TEST_DEVICE_NAME}' to NetIM")
	try:
		response = netim.add_device_without_detail(TEST_DEVICE_NAME, TEST_DEVICE_ADDRESS)
	except NameError as e:
		logger.debug(f"NameError: {e}")
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
	except:
		logger.info("Exception when adding device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	try:
		device_id = netim.get_device_id_by_device_name(TEST_DEVICE_NAME)
	except:
		logger.info("Exception when getting Device ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	check(bool(device_id != -1), f"Device '{TEST_DEVICE_NAME}' should be visible in Device Manager.")

	# Not sure how long it takes to complete auto-configuration; may be too long to wait in the test case
	# AUTOCONFIGURE DEVICE
	#prompt(f"Autoconfiguring Device '{TEST_DEVICE_NAME}' in NetIM")
	#try:
	#	response = netim.autoconfigure_devices([TEST_DEVICE_NAME])
	#except AttributeError as e:
	#	logger.debug(f"AttributeError: {e}")
	#except:
	#	logger.info("Exception when autoconfiguring device")
	#	logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	#
	#prompt("Providing NetIM time to process ...")
	#time.sleep(TEST_WAIT * 30)
	#
	#device_access_info = netim.get_device_access_info_by_device_id(device_id)
	#has_community_string = False
	#if 'hasSnmpCommunityString' in device_access_info:
	#	has_community_string = device_access_info['hasSnmpCommunityString']
	#check(bool(has_community_string == True), f"Device '{TEST_DEVICE_NAME}' is not yet configured")

	# This call is currently not working
	# UPDATE DEVICE TIMEZONE
	#prompt(f"Updating Device '{TEST_DEVICE_NAME}' timezone")
	#try:
	#	response = netim.update_device_timezone(device_id, 'America/Chicago', 'Central Standard Time')
	#except AttributeError as e:
	#	logger.debug(f"AttributeError: {e}")
	#except KeyError as e:
	#	logger.debug(f"KeyError: {e}")
	#except NameError as e:
	#	logger.debug(f"NameError: {e}")
	#except TypeError as e:
	#	logger.debug(f"TypeError: {e}")
	#except:
	#	logger.info("Exception when updating device timezone")
	#	logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	#
	#prompt("Providing NetIM time to process ...")
	#time.sleep(TEST_WAIT)
	#
	#try:
	#	device = netim.get_device_by_id(device_id)
	#except AttributeError as e:
	#	logger.debug(f"AttributeError: {e}")
	#except:
	#	logger.info("Exception when getting Device by ID")
	#	logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	#
	# Test is failing
	#check(bool(device['timeZone'] == 'America/Chicago'), "Timezone not updated.")

	# ADD GROUP AND CONFIRM
	prompt(f"Adding Group '{TEST_GROUP_NAME}' to NetIM")
	try:
		response = netim.add_group(TEST_GROUP_NAME)
	except NameError as e:
		logger.debug(f"NameError: {e}")
	except:
		logger.info("Exception when adding group")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	group_id = -1
	try:
		group_id = netim.get_group_id_by_group_name(TEST_GROUP_NAME)
	except TypeError as e:
		logger.info(f"TypeError: {e}")
	except:
		logger.info("Exception when getting Group ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	check(bool(group_id != -1), f"Group {TEST_GROUP_NAME} should be visible in Search.")

	# ADD DEVICES TO GROUP AND CONFIRM
	prompt(f"Add devices to Group '{TEST_GROUP_NAME}'")
	try:
		netim.add_devices_to_group(TEST_GROUP_NAME, [device_id])
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
	except:
		logger.info("Exception when adding devices to group")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	group_devices = []
	try:
		group_devices = netim.get_devices_in_group(TEST_GROUP_NAME)
	except NameError as e:
		logger.info(f"NameError: {e}")
		raise
	except:
		logger.info(f"Exception when getting devices for Group '{TEST_GROUP_NAME}'")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise

	result = False
	if len(group_devices) > 0:
		for group_device in group_devices:
			if int(group_device['id']) == int(device_id):
				result = True
	check(result, f"Device '{TEST_DEVICE_NAME}' should be visible in Group '{TEST_GROUP_NAME}'")	

	# UPDATE DEVICE LOCATION
	prompt(f"Update Device '{TEST_DEVICE_NAME}' city, state, country")
	try:
		country_id, region_id, city_id = netim.get_location_ids(TEST_COUNTRY_NAME, \
			TEST_REGION_NAME, TEST_CITY_NAME)
		response = netim.update_device_location(device_id, country_id, region_id, city_id)
	except:
		logger.info("Exception when updating device location")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	
	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	try:
		device = netim.get_device_by_id(device_id)
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
	except:
		logger.info("Exception when getting Device by ID")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	check(bool(device['city'] == city_id), "Location not updated.")

	# REMOVE DEVICES FROM GROUP AND CONFIRM
	prompt(f"Remove devices from Group '{TEST_GROUP_NAME}'")
	try:
		netim.remove_devices_from_group(TEST_GROUP_NAME, [device_id])
	except:
		logger.info("Exception when removing devices from group")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	group_devices = []
	try:
		group_devices = netim.get_devices_in_group(TEST_GROUP_NAME)
	except:
		logger.info(f"Exception when getting devices for Group '{TEST_GROUP_NAME}'")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	check(bool(len(group_devices) == 0), "")
	
	# # # TEST CUSTOM ATTRIBUTES
	test_custom_attributes_apis(netim, device_id, group_id)
		
	# DELETE GROUP AND CONFIRM
	prompt(f"Delete Group '{TEST_GROUP_NAME}' from NetIM")
	try:
		netim.delete_group(TEST_GROUP_NAME)
	except:
		logger.info("Exception when deleting group name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	group_id = -1
	try:
		group_id = netim.get_group_id_by_group_name(TEST_GROUP_NAME)
	except:
		logger.info("Exception when getting Group ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	check(bool(group_id == -1), f"Group '{TEST_GROUP_NAME}' should no longer be visible in Search.")

	# DELETE DEVICE AND CONFIRM
	
	prompt(f"Delete test Device '{TEST_DEVICE_NAME}' from NetIM") 
	try:
		response = netim.delete_device(TEST_DEVICE_NAME)
	except:
		logger.info("Exception when deleting device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt("Providing NetIM time to process ...")
	time.sleep(TEST_WAIT)

	try:
		device_id = netim.get_device_id_by_device_name(TEST_DEVICE_NAME)
	except:
		logger.info("Exception when getting Device ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	check(bool(device_id == -1), f"Device '{TEST_DEVICE_NAME}' should no longer be visible in Device Manager.")

	return

def test_add_delete_device(netim):
	prompt(f"Adding test Device '{TEST_DEVICE_NAME}' to NetIM")
	try:
		response = netim.add_device_without_detail(TEST_DEVICE_NAME, TEST_DEVICE_ADDRESS)
	except NameError as e:
		logger.debug(f"NameError: {e}")
	except TypeError as e:
		logger.debug(f"TypeError: {e}")
	except:
		logger.info("Exception when adding device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	time.sleep(TEST_WAIT)
	prompt(f"Checking that test Device '{TEST_DEVICE_NAME}' was added successfully to NetIM")

	device_id = -1
	try:
		device_id = int(netim.get_device_id_by_device_name(TEST_DEVICE_NAME))
	except:
		logger.info("Exception when getting Device ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	check(bool(device_id != -1), f"Device '{TEST_DEVICE_NAME}' should be visible in Device Manager.")

	prompt(f"Delete test Device '{TEST_DEVICE_NAME} from NetIM") 
	try:
		response = netim.delete_device(TEST_DEVICE_NAME)
	except:
		logger.info("Exception when deleting device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	return

def test_archives_apis(netim, device_name):

	device_id = int(netim.get_device_id_by_device_name(device_name))
	if device_id < 0:
		logger.info("Device name '{device_name}' not found in NetIM.")
		raise Exception("Device name '{device_name}' not found in NetIM.")
		
	archives = netim.get_archives_by_device_id(device_id, file_filter='ALL')
	archive_count = len(archives)
	prompt(f"Device name '{device_name}' has {archive_count} archive(s).")

	file = netim.get_archive_file_by_id(archives[0]['id'])
	prompt("The first line in the file in the first archive in the list is:")
	prompt(file.split('\n')[0])

	return

def test_locations_apis(netim):

	prompt("Location United States, Virginia, Richmond should exist")
	check(netim.check_location_exists("United States of America", "Virginia", "Richmond"), "Location not found")

	prompt("Location for France, Normandy should exist")
	check(netim.check_location_exists("France", "Normandy"), "Location not found")
	
	prompt("Location for South Africa should exist")
	check(netim.check_location_exists("South Africa"), "Location not found")

	prompt("Location for Wakanda should not exist")
	check(not netim.check_location_exists("Wakanda"), "Location found")

	return

def test_metric_apis(netim):

	metric_classes_json = netim.get_all_metric_classes()
	if 'items' in metric_classes_json:
		metric_classes = metric_classes_json['items']
	metric_classes_count = len(metric_classes)
	prompt(f"There are {metric_classes_count} metric classes in NetIM.")

	metric_class_name = 'Interface Utilization and Throughput'
	metric_class_id = netim.get_metric_class_id_by_name(metric_class_name)
	metrics_json = netim.get_metrics_from_metric_class(metric_class_id)
	if 'items' in metrics_json:
		metrics = metrics_json['items']
	else:
		metrics = metrics_json
	metric_count = len(metrics)
	prompt(f"There are {metric_count} metrics in metric class '{metric_class_name}' in NetIM.")

	end_time = int(time.time() * 1000)
	start_time = end_time - 1000*60*60
	metric_data = netim._get_metric_data(start_time=start_time, end_time=end_time, metric_class=metric_class_id, 
		metrics=[metrics[2]['id'], metrics[3]['id']], 
		element_ids=[TEST_POLLED_DEVICE_ID], sort_order='ASCENDING')

	return

def main():

	parser = argparse.ArgumentParser(description='Python utility to test SteelScript NetIM')
	parser.add_argument('--netim_hostname', help='DNS resolvable hostname or IP address of NetIM')
	parser.add_argument('--netim_username', help='NetIM username')
	parser.add_argument('--netim_password', help='NetIM password')
	args = parser.parse_args()

	if args.netim_hostname == None:
		prompt("No hostname was specified. Use --netim_hostname argument to provide a hostname. Exiting ...")
	if args.netim_username == None:
		prompt("No username was specified. Use --netim_username argument to provide a username. Exiting ...")

	netim_password = args.netim_password
	if netim_password == None or netim_password == "":
		netim_password = getpass.getpass()

	prompt("Authenticating to NetIM")
	try:
		auth = UserAuth(args.netim_username, netim_password, method=Auth.BASIC)
		netim = NetIM(args.netim_hostname, auth)
	except RvbdHTTPException as e:
		logger.debug(f"RvbdHTTPException: {e}")
		raise
	except NameError as e:
		logger.debug(f"NameError: {e}")
		raise
	except:
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		raise

	prompt(f"Getting all devices from NetIM")
	netim_devices_json = netim.get_all_devices()
	netim_devices = []
	if netim_devices_json != None and 'items' in netim_devices_json:
		netim_devices = netim_devices_json['items']
	netim_devices_count = len(netim_devices)
	prompt(f"There are {netim_devices_count} devices in NetIM.")
	prompt("Beginning test execution ...")
	prompt("")

	test_archives_apis(netim, TEST_ARCHIVE_DEVICE)
	test_devices_and_groups_apis(netim, netim_devices)
	test_locations_apis(netim)
	test_metric_apis(netim)

	return

if __name__ == "__main__":
	main()


