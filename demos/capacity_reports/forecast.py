
import logging
import sys

logging.captureWarnings(True)
logger = logging.getLogger(__name__)

#logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

def read_yml(yml):
	try:
		import yaml
	except ImportError as e:
		raise Exception("The 'yaml' library could not be imported. ImportError: {e}")

	try:
		if yml != None:
			with open(yml) as filehandle:
				yml_file = yaml.safe_load(filehandle)
		else:
			yml_file = None
	except FileNotFoundError as e:
		logger.debug(f"FileNotFoundError: {e}")
		yml_file = None

	return yml_file

def get_credentials(yml):
	credentials = read_yml(yml)
	
	netim_hostname = None
	if 'netim_hostname' in credentials:
		netim_hostname = credentials['netim_hostname']
	else:
		raise Exception("Missing 'netim_hostname' in configuration")
	netim_username = None
	if 'netim_username' in credentials:
		netim_username = credentials['netim_username']
	else:
		raise Exception("Missing 'netim_username' in configuration")
	if 'netim_password' in credentials:
		netim_password = credentials['netim_password']
	else:
		raise Exception("Missing 'netim_password' in configuration")

	return netim_hostname, netim_username, netim_password

def authenticate_to_netim(netim_hostname, netim_username, netim_password):

	try:
		import steelscript
		from steelscript.common.service import UserAuth, Auth
		from steelscript.common.exceptions import RvbdHTTPException
		from steelscript.netim.core import NetIM
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")

	try:
		auth = UserAuth(netim_username, netim_password, method=Auth.BASIC)
		netim = NetIM(netim_hostname, auth)
	except RvbdHTTPException as e:
		logger.debug(f"RvbdHTTPException: {e}")
		raise
	except NameError as e:
		logger.debug(f"NameError: {e}")
		raise
	except:
		logger.debug(f"Uexpected error {sys.exc_info()}")
		raise

	return netim

def import_report_times(config_yml):

	try:
		from datetime import datetime
		import yaml
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")

	config = None
	if config_yml != None:
		config = read_yml(config_yml)

	start_time_str = None
	if 'start_time' in config:
		start_time_str = config['start_time']
	end_time_str = None
	if 'end_time' in config:
		end_time_str = config['end_time']

	try:
		start_time = round(datetime.strptime(start_time_str, '%m-%d-%Y %H:%M:%S').timestamp() * 1000)
	except:
		logger.debug(f"Start time configuration '{start_time_str}' is invalid")
		raise 
	try:
		end_time = round(datetime.strptime(end_time_str, '%m-%d-%Y %H:%M:%S').timestamp() * 1000)
	except:
		logger.debug(f"End time configuration '{end_time_str}' is invalid")
		raise

	return start_time, end_time

def get_data_granularity(config_yml):
	try:
		import yaml
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")

	config = None
	if config_yml !=None:
		config = read_yml(config_yml)

	granularity = None
	if 'granularity' in config:
		granularity = config['granularity']

	return granularity

def get_data_rollup(config_yml):
	try:
		import yaml
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")

	config = None
	if config_yml !=None:
		config = read_yml(config_yml)

	rollup = None
	if 'rollup' in config:
		rollup = config['rollup']
		if rollup == 'minimum':
			return 'aggregateMinRollup'
		elif rollup == 'maximum':
			return 'aggregateMaxRollup'
		elif rollup == 'average':
			return 'aggregateAvgRollup'
		elif rollup == '95th percentile':
			return 'aggregatePctlRate95Rollup'
		elif rollup == '98th percentile':
			return 'aggregatePctlRate98Rollup'
		else:
			logger.info(f"Rollup configuration {rollup} is invalid or missing. Using average.")

	return 'aggregateAvgRollup'

def import_sites(sites_yml):
	
	sites = None
	if sites_yml != None:
		sites = read_yml(sites_yml)
	return sites

def pull_metric_data_for_sites(netim, sites, start_time, end_time, metrics_to_pull=[], metric_epoch_enum='RAW',
	rollup_criterias='aggregateAvgRollup'):

	if 'sites' in sites:
		sites_list = sites['sites']
	else:
		sites_list = []
		logger.info("Unexpected format in list of sites for which to pull metric data.")

	for site in sites_list:
		if 'name' in site:
			site_name = site['name']
		if 'alias' in site:
			alias = site['alias']

		interface_types = ['active', 'backup']
		for interfaces_type in interface_types:
			device_and_interfaces = None
			if interfaces_type in site:
				device_and_interfaces = site[interfaces_type]

			if device_and_interfaces != None:
				device_name = interface_name = None
				for device_and_interface in device_and_interfaces:
					if 'device' in device_and_interface:
						device_name = device_and_interface['device']
					if 'interface' in device_and_interface:
						interface_name = device_and_interface['interface']
		
					interface_json = netim.get_device_interface_by_device_name_and_interface_name(device_name,
						interface_name)
					interface_id = int(interface_json['id'])
					if interface_id != -1:
						device_and_interface['interface_metric_data'] = \
							netim.get_interface_metrics(interface_id, \
							start_time=start_time, end_time=end_time, \
							metric_epoch_enum=metric_epoch_enum, \
							metrics=metrics_to_pull, \
							rollup_criterias=rollup_criterias)
					else:
						logger.info(f"Interface {interface_name} on device {device_name} not found in NetIM")

	return sites

def create_forecast(site_name, device_name, interface_name, interface_type, metric_display_name, units, dates, values, output_dir='forecast'):
	try:
		from datetime import datetime
		import html
		import os
		import pandas as pd
		import matplotlib.pyplot as plt
		from prophet import Prophet
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")
	except:
		raise

	# Set up forecasting model which requires ds (datestamp) and y (numeric values)
	ds = pd.to_datetime(dates, unit='ms')
	prophet_df = pd.DataFrame({'ds':ds, 'y':values})

	model = Prophet(interval_width=0.95, growth='linear', daily_seasonality=True, weekly_seasonality=True, yearly_seasonality=True,
		seasonality_mode='multiplicative')
	model.fit(prophet_df)
	
	# Create future time windows
	start_time = min(dates) / 1000
	start_timestamp = datetime.fromtimestamp(start_time)
	end_time = max(dates) / 1000
	end_timestamp = datetime.fromtimestamp(end_time)
	duration = end_time - start_time
	# Forecast for 1/3 more time than historical data
	future_duration = duration / 3.0

	if len(dates) > 2:
		time_difference = int(round((dates[1] - dates[0]) / 1000)) # in seconds
		if time_difference < 15:
			interval = 1 # one second
			interval_str = "1S"
		elif time_difference >= 15 and time_difference < 1800:
			interval = 60 # one minute
			interval_str = "1M"
		elif time_difference >= 1800 and time_difference < 43200:
			interval = 3600 # one hour
			interval_str = "1H"
		elif time_difference >= 43200 and time_difference < 302400:
			interval = 86400 
			interval_str = '1D'
		elif time_difference >= 302400:
			interval = 604800
			interval_str = '1W'
		num_intervals = int(round(future_duration / interval))

	else:
		raise Exception("Not enough historical data to forecast")

	future_df = model.make_future_dataframe(periods=num_intervals, freq=interval_str, include_history=True)
	forecast_df = model.predict(future_df)
	
	# Clamp values to zero
	for col in ['yhat', 'yhat_lower', 'yhat_upper']:
		forecast_df[col] = forecast_df[col].clip(lower=0.0)

	title = f'{device_name} - {interface_name} - {interface_type}'
	predict_fig = model.plot(forecast_df, xlabel='Date', ylabel='{metric}')
	predict_ax = predict_fig.gca()
	predict_ax.set_title(title, size=16)

	# Need to make these dates HTML friendly so change format slightly	
	start_time_str = start_timestamp.strftime('%m%d%Y%H%M%S')
	end_time_str = end_timestamp.strftime('%m%d%Y%H%M%S')
				
	device_name_html = html.escape(device_name)
	interface_name_html = html.escape(interface_name)
	### Handle '/' in interface name? Better way?
	interface_name_html = interface_name_html.replace('/', '_')
	metric_display_name_html = metric_display_name.replace(' ', '-')

	filename = f'{device_name_html}_{interface_name_html}_{metric_display_name_html}_{start_time_str}_{end_time_str}.png'
	directory = f'{os.getcwd()}/{output_dir}'
	if not os.path.exists(directory):
		try:
			os.makedirs(directory)
		except OSError as e:
			if e.errno != errno.EEXIST:
				raise
	path = f'{directory}/{filename}'
	plt.savefig(f'{path}', bbox_inches='tight', pad_inches=0.5)
	plt.close()
			
	return path

def forecast(sites, metrics_to_forecast=[], metric_display_names=None, threshold=90, output_dir='forecast', granularity='RAW',
	rollup_criterias=[], start_time=None, end_time=None, future_duration=None):

	try:
		from datetime import datetime
		import os
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")
	except:
		raise
		
	if 'sites' in sites:
		sites_to_forecast = sites['sites']
	else:
		logger.info(f"Unexpected format in list of sites to report")
		sites_to_forecast = []
	
	sites_with_filenames = {}
	for site in sites_to_forecast:
		if 'name' in site:
			site_name = site['name']
		else:
			logger.debug("No 'name' in site")
			coontinue

		filenames = []
		# For now, only forecast 'active' interfaces
		interface_types = ['active']
		for interface_type in interface_types:
			if interface_type in site:
				devices_and_interfaces = site[interface_type]
			else:
				continue

			device_name = interface_name = None
			for device_and_interface in devices_and_interfaces:
				if 'device' in device_and_interface:
					device_name = device_and_interface['device']
				if 'interface' in device_and_interface:
					interface_name = device_and_interface['interface']

				interface_metric_data = None
				if 'interface_metric_data' in device_and_interface:
					interface_metric_data = device_and_interface['interface_metric_data']
				if interface_metric_data != None:
					for metric_data in interface_metric_data:
						metric = None
						if 'metric' in metric_data:
							metric = metric_data['metric']
						if metrics_to_forecast != None and metric not in metrics_to_forecast:
							continue
						
						units = None
						if 'units' in metric_data:
							units = metric_data['units']
						dates = None
						if 'datetime_index' in metric_data:
							dates = metric_data['datetime_index']
						values = None
						if 'values' in metric_data:
							values = metric_data['values']
						
						metric_display_name = metric
						if metric_display_names != None:
							if metric in metric_display_names:
								metric_display_name = metric_display_names[metric]
						
						filename = create_forecast(site_name, device_name, interface_name, interface_type, metric_display_name, units, 
							dates, values, output_dir='forecast')
						filenames.append(filename)

		sites_with_filenames[site_name] = filenames

	body = ''
	for site_name, filenames in sites_with_filenames.items():
		for filename in filenames:
			body += f'<br><img src="{filename}"><br>'

	directory = f'{os.getcwd()}/{output_dir}'
	if not os.path.exists(directory):
		try:
			os.makedirs(directory)
		except OSError as e:
			if e.errno != errno.EEXIST:
				raise
	index_html = f'{directory}/index.html'
	with open(index_html, 'w') as index_html_f:
		note = 'Reporting on: '
		i = 0
		for metric in metrics_to_forecast:
			if i > 0:
				note += ', '
			if metric in metric_display_names:
				note += f'{metric_display_names[metric]}'
			else:
				note += {metric}
			i += 1
		note += '<br>'
		note += f'Threshold: {threshold}<br>' ### Will need to be per-metric
		note += f'Granularity: {granularity}<br>'
		note += f'Rollup: {rollup_criterias[0]}<br>'
		note += f'Model: Linear<br>'
		note += f'Seasonality: Multiplicative, with daily, weekly, and monthly seasonality<br>'
		start_datetime = datetime.fromtimestamp(start_time / 1000)
		end_datetime = datetime.fromtimestamp(end_time / 1000)
		start_time_str = start_datetime.strftime('%m/%d/%Y %H:%M:%S')
		end_time_str = end_datetime.strftime('%m/%d/%Y %H:%M:%S')
		note += f'Historical Data Period: {start_time_str} to {end_time_str}'
		#if future_duration != None:
		#	forecast_end_time = datetime.from_timestamp((end_time / 1000) + future_duration)
		#	forecast_end_time_str = forecast_end_time.strftime('%m/%d/%Y %H:%M:%S')
		#	note += f'Forecasting Period: {end_time_str} to {forecast_end_time_str}'
		title = 'Forecast Reports'
		page = f'<title>{title}</title><html>{note}<body>{body}</body></html>'
		index_html_f.write(page)
	
	return

def run(config_yml, sites_yml):

	# Read YAML configuration files
	sites = import_sites(sites_yml)
	start_time, end_time = import_report_times(config_yml)
	hostname, username, password = get_credentials(config_yml)
	granularity = get_data_granularity(config_yml)
	if granularity != 'RAW':
		rollup_criterias = [get_data_rollup(config_yml)]

	netim = authenticate_to_netim(hostname, username, password)

	# Pull input data from source
	# Pull data directly from sources
	sites_with_metric_data = pull_metric_data_for_sites(netim, sites, start_time, end_time,
		metrics_to_pull=['utilizationIn', 'utilizationOut'], metric_epoch_enum=granularity,
		rollup_criterias=rollup_criterias)
	logger.info(f"There are {len(sites_with_metric_data['sites'])} sites configured for reporting")

	# Forecast
	forecast(sites_with_metric_data, metrics_to_forecast=['utilizationIn', 'utilizationOut'],
		metric_display_names={'utilizationIn':'Utilization Inbound', 'utilizationOut':'Utilization Outbound'},
		threshold=90, granularity=granularity, rollup_criterias=rollup_criterias, 
		start_time=start_time, end_time=end_time)

	# Clean up

	return

def main():
	try:
		import argparse
	except ImportError as e:
		raise Exception("The 'argparse' library could not be imported. ImportError: {e}")

	parser = argparse.ArgumentParser(description="Python utility for capacity analysis using Riverbed data")
	parser.add_argument('--config_yml', help='Report configuration information')
	parser.add_argument('--sites_yml', help='Site configuration information')
	args = parser.parse_args()

	#try:
	run(args.config_yml, args.sites_yml)
	logger.info("Success")
	#except:
	#	logger.debug(f"Uexpected error {sys.exc_info()}")
	#	logger.info("Failure")

	return

if __name__ == "__main__":
	main()
