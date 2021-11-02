
import logging
import sys

logging.captureWarnings(True)
logger = logging.getLogger(__name__)

#logging.basicConfig(stream=sys.stdout, level=logging.INFO)
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

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

def create_graph(site_name, device_name, interface_name, interface_type, metric_display_name, units, dates, values, output_dir='report'):
	try:
		from datetime import datetime
		import html
		import os
		import pandas as pd
		import matplotlib.pyplot as plt
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")
	except:
		raise

	# Build plots
	num_plots = 1
	fig, axs = plt.subplots(num_plots, 1, sharex=True, figsize=(10,num_plots*3))
	fig.suptitle(f'{device_name} - {interface_name} - {interface_type}', fontsize=16)

	values_header = f"{metric_display_name} ({units})"
	site_df = pd.DataFrame({'timestamp':dates, values_header:values})
	site_df['Date'] = pd.to_datetime(site_df['timestamp'], \
		unit='ms').dt.strftime('%m-%d-%Y %H:%M:%S')

	site_df.plot(x='Date', y=values_header, \
		fontsize=6, legend=False, title=values_header, \
		grid=True, rot=30)

	x_axis = axs.get_xaxis()
	x_label = x_axis.get_label()
	x_label.set_visible(False)

	# Need to make these dates HTML friendly so change format slightly	
	start_time = datetime.fromtimestamp(min(dates) / 1000)
	end_time = datetime.fromtimestamp(max(dates) / 1000)
	start_time_str = start_time.strftime('%m%d%Y%H%M%S')
	end_time_str = end_time.strftime('%m%d%Y%H%M%S')
				
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

def create_site_summary(site, metrics_to_report=None, metric_display_names=None, threshold=90):

	summary = {}

	site_name = None
	if 'name' in site:
		site_name = site['name']

	interface_types = ['active', 'backup']
	for interface_type in interface_types:
		if interface_type in site:
			device_and_interfaces = site[interface_type]
		else:
			continue
	
		device_name = interface_name = None
		for device_and_interface in device_and_interfaces:
			if 'device' in device_and_interface:
				device_name = device_and_interface['device']
			if 'interface' in device_and_interface:
				interface_name = device_and_interface['interface']
			interface_metric_data = None
			if 'interface_metric_data' in device_and_interface:
				interface_metric_data = device_and_interface['interface_metric_data']
			if interface_metric_data != None:
				# Set up return structure
				if device_name not in summary:
					summary[device_name] = {}
				if interface_name not in summary[device_name]:
					summary[device_name][interface_name] = {}
				summary[device_name][interface_name]['type'] = interface_type

				for metric_data in interface_metric_data:
					if 'metric' in metric_data:
						metric = metric_data['metric']
					# For now, filter and report only on utilization
					if metrics_to_report != None and metric not in metrics_to_report:
						continue

					if 'object_id' in metric_data:
						interface_id = metric_data['object_id']
					units = None
					if 'units' in metric_data:
						units = metric_data['units']
					if 'datetime_index' in metric_data:
						datetime_index = metric_data['datetime_index']
					if 'values' in metric_data:
						values = metric_data['values']
					value_map = None
					if 'value_map' in metric_data:
						value_map = metric_data['value_map']

					metric_display_name = metric
					if metric_display_names != None:
						if metric in metric_display_names:
							metric_display_name = metric_display_names[metric]
			
					samples_above_threshold = samples_elevated = samples_low = 0
					low_value = None
					high_value = None
					for value in values:
						# Calculate min, max, average of data points
						if low_value == None or value < low_value:
							low_value = value
						if high_value == None or value > high_value:
							high_value = value

						# Calculate percentage of data points within thresholds
						if value > threshold:
							samples_above_threshold += 1
						elif value > float(threshold)/2:
							samples_elevated += 1
						else:
							samples_low += 1

					report = {}
					report['units'] = units
					report['avg'] = round(sum(values)/len(values), 2)
					report['min'] = low_value
					report['max'] = high_value
					report['sample_count'] = len(values)
					report['above_count'] = samples_above_threshold
					report['halfway_count'] = samples_above_threshold
					report['low_count'] = samples_low
					report['graph'] = create_graph(site_name, device_name, interface_name, interface_type, metric_display_name,
						units, datetime_index, values)
					if 'metrics' not in summary[device_name][interface_name]:
						summary[device_name][interface_name]['metrics'] = {}
					summary[device_name][interface_name]['metrics'][metric_display_name] = report

	return summary

def report(sites, metrics_to_report=[], metric_display_names=None, threshold=90, output_dir='report', granularity='RAW',
	rollup_criterias=[], start_time=None, end_time=None):

	try:
		from datetime import datetime
		import os
	except ImportError as e:
		raise Exception(f"The required Python libraries could not be imported. ImportError: {e}")
	except:
		raise
		
	if 'sites' in sites:
		sites_to_report = sites['sites']
	else:
		logger.info(f"Unexpected format in list of sites to report")
		sites_to_report = []
	
	sites_with_summary = {}
	sites_with_filenames = {}
	for site in sites_to_report:
		sites_with_summary[site['name']] = create_site_summary(site, metrics_to_report=metrics_to_report,
			metric_display_names=metric_display_names, threshold=threshold)


	directory = f'{os.getcwd()}/{output_dir}'
	if not os.path.exists(directory):
		try:
			os.makedirs(directory)
		except OSError as e:
			if e.errno != errno.EEXIST:
				raise
	index_html = f'{directory}/index.html'
	with open(index_html, 'w') as index_html_f:
		body = ''
		for site_name, summary in sites_with_summary.items():
			table_headers = ''
			table_headers += '<th width="20%">Device</th><th width="20%">Interface</th><th>Type</th><th>Metric</th>'
			table_headers += '<th>Avg</th><th>Min</th><th>Max</th>'
			table_headers += '<th>Violation</th>'
			table_headers += '<th>Percent of Samples Above Threshold</th><th>Percent of Samples Halfway to Threshold</th><th>Percent of Samples Less Than Halfway to Threshold</th>'
			table_header_row = f'<tr>{table_headers}</tr>'
	
			table_rows = ''	
			for device_name, interfaces in summary.items():	
				table_row_divisions = ''
				table_row_divisions += f'<td>{device_name}</td><td></td><td></td><td></td><td></td>'
				table_row_divisions += '<td></td><td></td><td></td>'
				table_row_divisions += '<td></td><td></td><td></td>'
				table_rows += f'<tr>{table_row_divisions}</tr>'
				
				for interface_name, interface_info in interfaces.items():
					interface_type = interface_info['type']
					metrics = interface_info['metrics']
					table_row_divisions = ''
					table_row_divisions += f'<td></td><td>{interface_name}</td><td>{interface_type}</td><td></td><td></td>'
					table_row_divisions += '<td></td><td></td><td></td>'
					table_row_divisions += '<td></td><td></td><td></td>'
					table_rows += f'<tr>{table_row_divisions}</tr>'

					for metric_name, report in metrics.items():
						violation = bool(report['above_count'] > 0)
						pct_above_threshold = int(round(report['above_count']/report['sample_count']*100,0))
						pct_halfway = int(round(report['halfway_count']/report['sample_count']*100,0))
						pct_low = int(round(report['low_count']/report['sample_count']*100,0))
						avg = report['avg']
						min = report['min']
						max = report['max']
						graph_filename = report['graph']
						units = report['units']

						table_row_divisions = ''
						table_row_divisions += f'<td></td><td></td><td></td><td><a href={graph_filename}>{metric_name}</a> ({units})</td>'
						table_row_divisions += f'<td width="6%" style="text-align:center">{avg}</td>'
						table_row_divisions += f'<td width="6%" style="text-align:center">{min}</td>'
						table_row_divisions += f'<td width="6%" style="text-align:center">{max}</td>'
						if violation == True:
							violation_style = ' bgcolor="red"'
						else:
							violation_style = ' bgcolor="green"'
						table_row_divisions += f'<td {violation_style}>{violation}</td>'
						table_row_divisions += f'<td width="8%" style="text-align:center">{pct_above_threshold}%</td>'
						table_row_divisions += f'<td width="8%" style="text-align:center">{pct_halfway}%</td>'
						table_row_divisions += f'<td width="8%" style="text-align:center">{pct_low}%</td>'
						table_rows += f'<tr>{table_row_divisions}</tr>'

			table_headers_and_rows = table_header_row + table_rows
			summary_table = f'<table style="width:80%">{table_headers_and_rows}</table>'

			body += f"<h2>Capacity Report for {site_name}</h2>"
			body += summary_table

		table_style = '<style>table, th, td {border: 1px solid black; border-collapse: collapse;} th, td {padding: 2px;}</style>'
		header = f'<head><h1>Site Capacity Reports</h1>{table_style}</head><br>'
		note = 'Reporting on: '
		i = 0
		for metric in metrics_to_report:
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
		start_datetime = datetime.fromtimestamp(start_time / 1000)
		end_datetime = datetime.fromtimestamp(end_time / 1000)
		start_time_str = start_datetime.strftime('%m/%d/%Y %H:%M:%S')
		end_time_str = end_datetime.strftime('%m/%d/%Y %H:%M:%S')
		note += f'Attempted Reporting Period: {start_time_str} to {end_time_str}'
		title = 'Site Capacity Reports'
		page = f'<title>{title}</title><html>{header}{note}<body>{body}</body></html>'
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

	# Run capacity report
	report(sites_with_metric_data, metrics_to_report=['utilizationIn', 'utilizationOut'],
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

	try:
		run(args.config_yml, args.sites_yml)
		logger.info("Success")
	except:
		logger.debug(f"Uexpected error {sys.exc_info()}")
		logger.info("Failure")

	return

if __name__ == "__main__":
	main()
