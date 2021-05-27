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
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

TEST_WAIT = 1
TEST_AUTOMATION = True

TEST_CUSTOM_ATTRIBUTE = 'Test Custom Attribute'
TEST_CUSTOM_ATTRIBUTE_DESCRIPTION = 'Test attribute created on device'
TEST_CUSTOM_ATTRIBUTE_VALUE = 'Test'
TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED = 'Changed'

TEST_DEVICE_NAME = 'testxyz'
TEST_DEVICE_ADDRESS = '10.1.150.TEST_WAIT'

TEST_GROUP_NAME = 'groupxyz'
TEST_SITE_NAME = 'Arlington'
TEST_CITY_NAME = 'Arlington'
TEST_REGION_NAME = 'Virginia'
TEST_COUNTRY_NAME = 'United States of America'

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

	prompt(f"Changing Custom Attribute Value in Custom Attribute '{TEST_CUSTOM_ATTRIBUTE}'")
	try:
		response = netim.update_custom_attribute_value(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_VALUE,
			TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED, device_ids=[test_device_id])
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

	# ADD GROUP AND CONFIRM

	prompt(f"Adding Group '{TEST_GROUP_NAME}' to NetIM")
	try:
		response = netim.add_group(TEST_GROUP_NAME)
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
	
	prompt(f"Delete test Device '{TEST_DEVICE_NAME} from NetIM") 
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

def main():

	parser = argparse.ArgumentParser(description='Python utility to test SteelScript NetIM')
	parser.add_argument('--netim_hostname', help='DNS resolvable hostname or IP address of NetIM')
	parser.add_argument('--netim_username', help='NetIM username')
	parser.add_argument('--netim_password', help='NetIM password')
	args = parser.parse_args()

	netim_password = args.netim_password
	if netim_password == None or netim_password == "":
		netim_password = getpass.getpass()

	prompt("Authenticating to NetIM")
	try:
		auth = UserAuth(args.netim_username, netim_password, method=Auth.BASIC)
		netim = NetIM(args.netim_hostname, auth)
	except RvbdHTTPException as e:
		logger.debug(f"RvbdHTTPException: {e}")
		return
	except NameError as e:
		logger.debug(f"NameError: {e}")
		return
	except:
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
		return

	prompt(f"Getting all devices from NetIM")
	netim_devices_json = netim.get_all_devices()
	netim_devices = []
	if netim_devices_json != None and 'items' in netim_devices_json:
		netim_devices = netim_devices_json['items']
	netim_devices_count = len(netim_devices)
	prompt(f"There are {netim_devices_count} devices in NetIM.")
	prompt("Beginning test execution ...")
	prompt("")

	test_devices_and_groups_apis(netim, netim_devices)
	#test_locations_apis(netim)

	return

if __name__ == "__main__":
	main()


