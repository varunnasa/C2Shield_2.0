import json
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import math
import logging 

logging.basicConfig(filename='flow_analysis.log', level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
def clients_by_volume_of_requests(log_file):
  """
  Clients with an unnecessary number of events compared with the rest 
  of the organisation may help to identify data transfers using DNS.
  """

  # Initialize a dictionary to store client volumes
  client_requests = {}

  # Open the DNS log file and parse JSON data line by line
  with open(log_file, 'r') as file:
      for line in file:
          # Parse JSON data from each line
          log_entry = json.loads(line)
          
          # Extract relevant fields
          src_ip = log_entry.get('id.orig_h')
          query_type = log_entry.get('query')
          
          # Increment client volume count
          if src_ip in client_requests:
              client_requests[src_ip] += 1
          else:
              client_requests[src_ip] = 1

  # Sort the client requests by volume
  sorted_requests = sorted(client_requests.items(), key=lambda x: x[1], reverse=True)

  # Print the top 10 clients by volume of requests
  print("Top 10 Clients by Volume of Requests:")
  for i in range(min(10, len(sorted_requests))):
      print(f"Client IP: {sorted_requests[i][0]}, Requests: {sorted_requests[i][1]}")
  # Open a file in write mode
  logging.info("Top 10 Clients by Volume of Requests:")
  for i in range(min(10, len(sorted_requests))):
      logging.info(f"Client IP: {sorted_requests[i][0]}, Requests: {sorted_requests[i][1]}")


# Example usage
# clients_by_volume_of_requests('/content/dns.ndjson')




# Example usage
#clients_by_volume_of_requests('/content/dns.ndjson')


def analyze_dns_log_record_type(log_file):
    """
    Changes in resource type behaviour for a client may point toward potential C&C or exfiltration activity.
    
    """
    # Initialize dictionaries to store counts of each resource record type
    record_counts = {}

    # Open the DNS log file and parse JSON data line by line
    with open(log_file, 'r') as file:
        for line in file:
            # Parse JSON data from each line
            log_entry = json.loads(line)
            
            # Extract relevant fields
            record_type = log_entry.get('qtype')

            # Increment count for the record type
            if record_type in record_counts:
                record_counts[record_type] += 1
            else:
                record_counts[record_type] = 1
    # Extract data for plotting
    record_types = list(record_counts.keys())
    counts = list(record_counts.values())

    
    print(f'{record_types} : {counts}')

    logging.info("Analyzed the dns record type:")
    logging.info(f'Record types: {record_types}, Counts: {counts}')
    
    

# Example usage
# analyze_dns_log('/content/dns.ndjson')


def analyze_packet_size_and_volume(json_file):

    """
    Events that have significant packet size and high volumes may 
    identify signs of exfiltration activity.

    A high number of requests, and/or large packets will be of interest. 
    """
    # Initialize an empty list to store the data
    data = []
    
    # Open the JSON file and parse each line as a separate JSON object
    with open(json_file, 'r') as file:
        for line in file:
            data.append(json.loads(line))
    
    # Create a DataFrame from the list of dictionaries
    events_df = pd.DataFrame(data)
    
    # Expand the multi-valued field
    events_df = events_df.explode('query')
    
    # Print the values in the 'query' field which are not strings
    non_string_queries = events_df[~events_df['query'].apply(isinstance, args=(str,))]
    print("Values in 'query' field which are not strings:")
    print(non_string_queries['query'])
    print()
    
    # Calculate the length of the query field only if it's a string
    events_df['queryLength'] = events_df['query'].apply(lambda x: len(x) if isinstance(x, str) else None)
    
    # Group the results by the length of the request and the source field
    grouped = events_df.groupby(['queryLength', 'id.orig_h']).size().reset_index(name='count')
    
    # Sort the results by the length of the request in descending order
    sorted_results = grouped.sort_values(by=['queryLength', 'count'], ascending=[False, False])
    
    # Limit the output to the first 1000 records
    top_1000 = sorted_results.head(1000)
    
    # Convert the DataFrame to a more readable format
    result_df = top_1000[['id.orig_h', 'queryLength', 'count']]


    logging.info("Analyzed packet size and volume: ")
    logging.info(result_df.to_string(index=False))

    return result_df

# Example usage
# Provide the path to the JSON file containing the events data
#result = analyze_packet_size_and_volume('/content/dns.ndjson')
#print(result)


def detect_beaconing_activity(log_file):
    """
    Looking for clients that show signs of beaconing out to C&C infrastructure. 
    Beaconing activity may occur when a compromised host ‘checks in’ with the 
    command infrastructure, possibly waiting for new instructions or updates to 
    the malicious software itself.

    It filters for queries with a low variance in time (VarianceBeaconTime < 60), 
    indicating consistent intervals between queries. 
    
    Additionally, it filters for queries with a count greater than 2 (count > 2) 
    and an average time gap greater than 1 second (AverageBeaconTime > 1.000). 
    
    These criteria help identify hosts that may be beaconing to C&C infrastructure.
    """
    # Initialize a dictionary to store query times for each query
    query_times = {}

    # Open the NDJSON log file and parse JSON data line by line
    with open(log_file, 'r') as file:
        for line in file:
            # Parse JSON data from each line
            log_entry = json.loads(line)
            
            # Extract relevant fields
            query = log_entry.get('query')
            timestamp = log_entry.get('ts')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp[:-1]).timestamp()
                except ValueError:
                    pass 
            # Update or initialize query time for the query
            if query in query_times:
                query_times[query].append(timestamp)
            else:
                query_times[query] = [timestamp]

    # Initialize lists to store beaconing queries
    beaconing_queries = []

    # Calculate average and variance of time gaps for each query
    for query, timestamps in query_times.items():
        # Filter out None values in timestamps
        timestamps = [ts for ts in timestamps if ts is not None]
        if len(timestamps) > 1:
            time_gaps = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_gap = sum(time_gaps) / len(time_gaps)
            variance = sum((gap - avg_gap) ** 2 for gap in time_gaps) / len(time_gaps)
            
            # Check for beaconing criteria
            if variance < 60 and len(time_gaps) > 2 and avg_gap > 1.0:
                beaconing_queries.append((query, variance, len(time_gaps), avg_gap))

    # Print beaconing queries
    logging.info("Analysis of Beaconing Activity:")
    if beaconing_queries:
        print("Beaconing Activity Detected:")
        logging.info("Beaconing Activity Detected:")
        print("{:<50} {:<20} {:<20} {:<20}".format("Query", "Variance", "Count", "Average Time Gap"))
        logging.info("{:<50} {:<20} {:<20} {:<20}".format("Query", "Variance", "Count", "Average Time Gap"))
        for query_info in beaconing_queries:
            print("{:<50} {:<20.3f} {:<20} {:<20.3f}".format(*query_info))
            logging.info("{:<50} {:<20.3f} {:<20} {:<20.3f}".format(*query_info))
    else:
        print("No beaconing activity detected.")
        logging.info("No beaconing activity detected.")

# Example usage
#detect_beaconing_activity('/content/dns.ndjson')


def detect_hosts_talking_to_beaconing_domains(log_file):

    """
    Identifying the number of hosts talking to a specific domain may help to
    identify potential BOT activity or help to identify the scope of hosts 
    currently compromised.
    """
    # Initialize dictionaries to store query times and hosts for each query
    query_info = {}

    # Open the NDJSON log file and parse JSON data line by line
    with open(log_file, 'r') as file:
        for line in file:
            # Parse JSON data from each line
            log_entry = json.loads(line)
            
            # Extract relevant fields
            query = log_entry.get('query')
            src_ip = log_entry.get('id.orig_h')
            timestamp = log_entry.get('ts')

            # Convert timestamp to Unix format if it's in datetime format
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp[:-1]).timestamp()
                except ValueError:
                    pass  # Skip if timestamp is not in ISO format

            # Update or initialize query information
            if query in query_info:
                query_info[query]['hosts'].add(src_ip)
                query_info[query]['timestamps'].append(timestamp)
            else:
                query_info[query] = {'hosts': {src_ip}, 'timestamps': [timestamp]}

    # Initialize a list to store results
    results = []

    # Calculate average and variance of time gaps for each query
    for query, info in query_info.items():
        num_hosts = len(info['hosts'])
        avg_gap = None
        variance = None

        if len(info['timestamps']) > 1:
            time_gaps = [info['timestamps'][i] - info['timestamps'][i-1] for i in range(1, len(info['timestamps']))]
            avg_gap = sum(time_gaps) / len(time_gaps)
            variance = sum((gap - avg_gap) ** 2 for gap in time_gaps) / len(time_gaps)

        if query is not None and num_hosts is not None and avg_gap is not None and variance is not None and variance < 60 and avg_gap > 0:
            results.append((query, num_hosts, avg_gap, variance))

    # Print results
    logging.info("Analysis of host that are talking to Beaconing domains: ")
    if results:
        print("Number of Hosts Talking to Beaconing Domains:")
        logging.info("Number of Hosts Talking to Beaconing Domains:")
        print("{:<50} {:<20} {:<20} {:<20}".format("Query", "NumHosts", "Average Time Gap", "Variance"))
        logging.info("{:<50} {:<20} {:<20} {:<20}".format("Query", "NumHosts", "Average Time Gap", "Variance"))
        for result in results:
            print("{:<50} {:<20} {:<20.3f} {:<20.3f}".format(*result))
            logging.info("{:<50} {:<20} {:<20.3f} {:<20.3f}".format(*result))
    else:
        print("No beaconing activity detected.")
        logging.info("No beaconing activity detected.")

# Example usage
#detect_hosts_talking_to_beaconing_domains('/content/dns.ndjson')


def detect_domains_with_lots_of_subdomains(log_file):
    # Open the DNS log file and parse ndjson data
    with open(log_file, 'r') as file:
        dns_logs = [json.loads(line) for line in file]

    # Initialize a dictionary to store subdomains for each domain
    domain_subdomains = {}

    # Loop through each DNS log entry
    for log_entry in dns_logs:
        # Extract relevant fields
        query = log_entry.get('query')
        if query is None:
            continue  # Skip if query is None
        domain_parts = query.split('.')
        if len(domain_parts) <= 1:
            continue  # Skip if the query does not contain a valid domain
        domain = '.'.join(domain_parts[1:])  # Get domain without top-level domain

        # Update or initialize subdomains for the domain
        if domain in domain_subdomains:
            subdomains = domain_subdomains[domain]
        else:
            subdomains = set()
        subdomains.add(query)
        domain_subdomains[domain] = subdomains

    # Calculate number of subdomains per domain
    hosts_per_domain = {domain: len(subdomains) for domain, subdomains in domain_subdomains.items()}

    # Sort domains by number of subdomains
    sorted_domains = sorted(hosts_per_domain.items(), key=lambda x: x[1], reverse=True)

    # Print results
    print("Domains with Lots of Subdomains:")
    logging.info("Domains with Lots of Subdomains:")
    print("{:<50} {:<20}".format("Domain", "Hosts Per Domain"))
    logging.info("{:<50} {:<20}".format("Domain", "Hosts Per Domain"))
    for domain, num_subdomains in sorted_domains:
        print("{:<50} {:<20}".format(domain, num_subdomains))
        logging.info("{:<50} {:<20}".format(domain, num_subdomains))

# Example usage
#detect_domains_with_lots_of_subdomains_from_ndjson('/content/dns.ndjson')



def detect_dns_tunneling_based_on_entropy(log_file):

    """
     Dns2cat and Iodine tool asks for a domain name that the attacker owns,
     and then encrypts, compresses, and chunks files. 
     To exfiltrate, it passes stolen information into DNS queries to randomized subdomains.
     We want to see how many random subdomains are being requested on the network and what they 
     look like to identify possible signs of attack. 
    """
    # Open the DNS log file and parse ndjson data
    with open(log_file, 'r') as file:
        dns_logs = [json.loads(line) for line in file]

    domain_info = {}

    # Loop through each DNS log entry
    for log_entry in dns_logs:
        # Extract relevant fields
        query = log_entry.get('query')
        if query is None:
          continue
        domain = query.split('.')[1:]  # Get domain without top-level domain
        domain = '.'.join(domain)
        subdomain = query.split('.')[0]

        # Update or initialize domain information
        if domain in domain_info:
            domain_info[domain]['subdomains'].add(subdomain)
            domain_info[domain]['entropy_scores'].append(shannon_entropy(subdomain))
            domain_info[domain]['subdomain_lengths'].append(len(subdomain))
        else:
            domain_info[domain] = {
                'subdomains': {subdomain},
                'entropy_scores': [shannon_entropy(subdomain)],
                'subdomain_lengths': [len(subdomain)]
            }

    # Filter domains based on specified criteria
    filtered_domains = {}
    for domain, info in domain_info.items():
        avg_entropy = sum(info['entropy_scores']) / len(info['entropy_scores'])
        avg_length = sum(info['subdomain_lengths']) / len(info['subdomain_lengths'])
        stdev_length = calculate_standard_deviation(info['subdomain_lengths'])
        
        if avg_entropy > 3 and avg_length > 20 and stdev_length < 2:
            filtered_domains[domain] = {
                'count': len(info['subdomains']),
                'avg_entropy': avg_entropy,
                'avg_length': avg_length,
                'stdev_length': stdev_length,
                'subdomain_samples': list(info['subdomains'])[:5]  # Take first 5 subdomains as samples
            }

    # Sort filtered domains by count
    sorted_domains = sorted(filtered_domains.items(), key=lambda x: x[1]['count'], reverse=True)

    # Print results
    print("Domains with DNS Tunneling Activity:")
    logging.info("Domains with DNS Tunneling Activity:")
    print("{:<50} {:<10} {:<15} {:<15} {:<15} {:<30}".format(
        "Domain", "Count", "Avg Entropy", "Avg Length", "Stdev Length", "Subdomain Samples"
    ))
    logging.info("{:<50} {:<10} {:<15} {:<15} {:<15} {:<30}".format(
        "Domain", "Count", "Avg Entropy", "Avg Length", "Stdev Length", "Subdomain Samples"
    ))
    for domain, info in sorted_domains:
        subdomain_samples_str = ', '.join(info['subdomain_samples'])
        print("{:<50} {:<10} {:<15.3f} {:<15.3f} {:<15.3f} {:<30}".format(
            domain, info['count'], info['avg_entropy'], info['avg_length'], info['stdev_length'], subdomain_samples_str
        ))
        logging.info("{:<50} {:<10} {:<15.3f} {:<15.3f} {:<15.3f} {:<30}".format(
            domain, info['count'], info['avg_entropy'], info['avg_length'], info['stdev_length'], subdomain_samples_str
        ))

def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def calculate_standard_deviation(data):
    """Calculate the standard deviation of a list of numbers."""
    mean = sum(data) / len(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    return variance ** 0.5

# Example usage
#detect_dns_tunneling_based_on_entropy('/content/dns.ndjson')
