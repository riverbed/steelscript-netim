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

TEST_CUSTOM_ATTRIBUTE = 'Test Custom Attribute'
TEST_CUSTOM_ATTRIBUTE_DESCRIPTION = 'Test attribute created on device'
TEST_CUSTOM_ATTRIBUTE_VALUE = 'Test'
TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED = 'Changed'

TEST_DEVICE_NAME = 'testxyz'
TEST_DEVICE_ADDRESS = '10.1.150.2'

TEST_GROUP_NAME = 'groupxyz'
TEST_SITE_NAME = 'Arlington'
TEST_CITY_NAME = 'Arlington'
TEST_REGION_NAME = 'Virginia'
TEST_COUNTRY_NAME = 'United States of America'

def prompt(step1, step2=""):
	print("")
	print(step1)
	if step2 != "":
		print(step2)
	input("Press <Enter> to test the associated APIs.")
	return

def check(success, check2=""):
	if success == True:
		print("Success")
	else:
		print("Failure")
	if check2 != "":
		print(check2)
	input("Press <Enter> when check is complete.")
	return

def test_custom_attributes_apis(netim):
	prompt(f"Getting all devices from NetIM")	
	netim_devices_json = netim.get_all_devices()
	netim_devices = []
	if netim_devices_json != None and 'items' in netim_devices_json:
		netim_devices = netim_devices_json['items']

	prompt(f"Adding custom attribute '{TEST_CUSTOM_ATTRIBUTE}' to all devices",
		"Under Configure / Device Manager, click on a device name, and choose Browse in the tabs that load." \
		" Custom Attributed are listed in the 2nd section.")
	attribute_id = netim.get_custom_attribute_id_by_name(TEST_CUSTOM_ATTRIBUTE)
	if int(attribute_id) < 0:
		response = netim.add_custom_attribute(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_DESCRIPTION)
		if response == None:
			logger.debug("Failed to create Custom Attribute in NetIM")

	prompt(f"Adding custom attribute values to custom attribute '{TEST_CUSTOM_ATTRIBUTE}'")
	updated_device_ids = [netim_device['id'] for netim_device in netim_devices]
	try:
		response = netim.add_custom_attribute_values(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_VALUE, 
			device_ids=updated_device_ids)
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
	except NameError as e:
		logger.debug(f"NameError: {e}")
	except:
		logger.debug("Exception when importing Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt(f"Changing custom attribute value in custom attribute '{TEST_CUSTOM_ATTRIBUTE}'")
	updated_device_ids = [netim_device['id'] for netim_device in netim_devices]
	try:
		response = netim.update_custom_attribute_value(TEST_CUSTOM_ATTRIBUTE, TEST_CUSTOM_ATTRIBUTE_VALUE,
			TEST_CUSTOM_ATTRIBUTE_VALUE_CHANGED)
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
	except NameError as e:
		logger.debug(f"NameError: {e}")
	except:
		logger.debug("Exception when importing Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	prompt(f"Deleting custom attribute values for custom attribute {TEST_CUSTOM_ATTRIBUTE}")
	try:
		response = netim.delete_custom_attribute(TEST_CUSTOM_ATTRIBUTE)
	except AttributeError as e:
		logger.debug(f"AttributeError: {e}")
	except NameError as e:
		logger.debug(f"NameError: {e}")
	except:
		logger.info("Exception when deleting Custom Attribute Values for devices")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	
	return	

def test_devices_apis(netim):

	prompt(f"Getting all devices from NetIM")	
	netim_devices_json = netim.get_all_devices()
	netim_devices = []
	if netim_devices_json != None and 'items' in netim_devices_json:
		netim_devices = netim_devices_json['items']

	prompt(f"Adding test device {TEST_DEVICE_NAME} to NetIM")
	try:
		response = netim.add_device_without_detail(TEST_DEVICE_NAME, TEST_DEVICE_ADDRESS)
	except:
		logger.info("Exception when adding device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	try:
		device_id = netim.get_device_id_by_device_name(TEST_DEVICE_NAME)
	except:
		logger.info("Exception when getting device ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	check(bool(device_id !=1), f"Device {TEST_DEVICE_NAME} should be visible in Device Manager.")

	prompt(f"Delete test device {TEST_DEVICE_NAME} from NetIM") 
	try:
		response = netim.delete_device(TEST_DEVICE_NAME)
	except:
		logger.info("Exception when deleting device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	return

def test_groups_apis(netim):

	prompt(f"Adding group {TEST_GROUP_NAME} to NetIM")
	try:
		response = netim.add_group(TEST_GROUP_NAME)
		time.sleep(3)
	except:
		logger.info("Exception when adding device")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	group_id = -1
	try:
		group_id = netim.get_group_id_by_group_name(TEST_GROUP_NAME)
	except TypeError as e:
		logger.info(f"TypeError: {e}")
	except:
		logger.info("Exception when getting group ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	check(bool(group_id != -1), f"Group {TEST_GROUP_NAME} should be visible in Search.")

	prompt(f"Delete group {TEST_GROUP_NAME} from NetIM")
	try:
		netim.delete_group(TEST_GROUP_NAME)
		time.sleep(3)
	except:
		logger.info("Exception when deleting group name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))

	group_id = -1
	try:
		group_id = netim.get_group_id_by_group_name(TEST_GROUP_NAME)
	except:
		logger.info("Exception when getting group ID by name")
		logger.debug("Unexpected error {}".format(sys.exc_info()[0]))
	check(bool(group_id == -1), f"Group {TEST_GROUP_NAME} should no longer be visible in Search.")

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


	test_devices_apis(netim)
	test_custom_attributes_apis(netim)
	test_groups_apis(netim)
	#test_locations_apis(netim)

	return

if __name__ == "__main__":
	main()


