import argparse
import sys
import os
import platform
import yaml
import logging
import time
import datetime
import sqlite3
import json
import flow_analysis
import pandas as pd
from src.analyst_profile import AnalystProfile
from src.packet_parser import PacketParser
from src.packet_capture import PacketCapture
from src.enrichment_engine import EnrichmentEngine
from src.detection_engine import DetectionEngine
from src.detection_reporter import DetectionReporter


def banner():
    print(r"""
 ____    _    ____   ___ ____  ____   ___  
/ ___|  / \  / ___| |_ _/ ___||  _ \ / _ \ 
\___ \ / _ \| |      | |\___ \| |_) | | | |
 ___) / ___ \ |___   | | ___) |  _ <| |_| |
|____/_/   \_\____| |___|____/|_| \_\\___/ 

    """)


def is_platform_supported():
    machine_platform = platform.system().lower()
    if not machine_platform.startswith('linux'):
        print(f"\n[{time.strftime('%H:%M:%S')}] [CRITICAL] Unsupported platform")
        logging.critical(f"Unsupported platform")
        print("\nExiting program ...\n")
        sys.exit(1)


def is_valid_file(filename, filetype):
    if not os.path.exists(filename):
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' does not exist")
        logging.error(f"Provided file '{filename}' does not exist")
        print("\nExiting program ...\n")
        sys.exit(1)
    else:
        if filetype == "pcap" or filetype == "log":  # check if the filetype is .pcap or .cap
            if not (filename.endswith(".pcap") or filename.endswith(".cap") or filename.endswith(".pcapng") or filename.endswith(".log")):
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a pcap/cap file")
                logging.error(
                    f"Provided file '{filename}' is not a pcap/cap file")
                print("\nExiting program ...\n")
                sys.exit(1)
        if filetype == "yml":
            if not filename.endswith(".yml") or filename.endswith(".yaml"):
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a yaml file")
                logging.error(f"Provided file '{filename}' is not a yaml file")
                print("\nExiting program ...\n")
                sys.exit(1)
    return True


def check_required_structure(analyst_profile, output_dir):
    base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    report_dir = os.path.join(base_relative_path, "reports")
    iocs_dir = os.path.join(base_relative_path, "iocs")
    config_dir = os.path.join(base_relative_path, "config")
    templates_dir = os.path.join(base_relative_path, "templates")

    domain_whitelist_path = os.path.join(base_relative_path, analyst_profile.domain_whitelist_path)
    c2_tls_certificate_values_path = os.path.join(base_relative_path, analyst_profile.c2_tls_certificate_values_path)
    report_template_path = os.path.join(base_relative_path, analyst_profile.report_template_path)

    if not output_dir == "reports":
        report_dir = output_dir

    if not os.path.isdir(report_dir):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{report_dir}' for storing analysis reports ...")
        logging.info(f"Creating '{report_dir}' for storing analysis reports")
        os.mkdir(report_dir)

    missing_update_script = False
    missing_config_files = False
    missing_report_template = False
    missing_files = False

    if not os.path.isdir(config_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{config_dir}' for storing config files ...")
        logging.info(f"Creating '{config_dir}' for config files")
        os.mkdir(config_dir)
        missing_config_files = True

    if not os.path.isdir(iocs_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{iocs_dir}' for storing IoCs ...")
        logging.info(f"Creating '{iocs_dir}' for storing IoCs")
        os.mkdir(iocs_dir)
        missing_update_script = True

    if not os.path.isdir(templates_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{templates_dir}' for analysis report template ...")
        logging.info(f"Creating '{templates_dir}' for analysis report template")
        os.mkdir(templates_dir)
        missing_report_template = True

    if not os.path.isfile(report_template_path):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Required file '{report_template_path}' is missing")
        logging.error(f"Required file '{report_template_path}' is missing")
        missing_files = True

    if not os.path.isfile(domain_whitelist_path):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Required file '{domain_whitelist_path}' is missing")
        logging.error(f"Required file '{domain_whitelist_path}' is missing")
        missing_files = True

    if not os.path.isfile(c2_tls_certificate_values_path):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Required file '{c2_tls_certificate_values_path}' is missing")
        logging.error(f"Required file '{c2_tls_certificate_values_path}' is missing")
        missing_files = True

    if missing_files:
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Required files are missing, please reference 'https://github.com/martinkubecka/C2Detective'")
        logging.error(f"Required files are missing, please reference 'https://github.com/martinkubecka/C2Detective'")
        print("\nExiting program ...\n")
        sys.exit(1)

    if missing_update_script:
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Download the missing update scripts from 'https://github.com/martinkubecka/C2Detective/tree/main/iocs'")
        logging.error(
            f"Download the missing update scripts from 'https://github.com/martinkubecka/C2Detective/tree/main/iocs'")
        print("\nExiting program ...\n")
        sys.exit(1)

    if missing_config_files:
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Create the missing config files or download them from 'https://github.com/martinkubecka/C2Detective/tree/main/config'")
        logging.error(
            f"Create the missing config files or download them from 'https://github.com/martinkubecka/C2Detective/tree/main/config'")
        print("\nExiting program ...\n")
        sys.exit(1)

    if missing_report_template:
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Create the missing analysis report temlapte or download it from 'https://github.com/martinkubecka/C2Detective/tree/main/templates'")
        logging.error(
            f"Create the missing config files or download them from 'https://github.com/martinkubecka/C2Detective/tree/main/templates'")
        print("\nExiting program ...\n")
        sys.exit(1)


def load_config(filename):
    try:
        with open(filename, "r") as ymlfile:
            config = yaml.safe_load(ymlfile)
            return config
    except yaml.parser.ParserError as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while parsing the configuration file")
        logging.error(f"Error occurred while parsing the configuration file ({e})")
        print("\nExiting program ...\n")
        sys.exit(1)


def arg_formatter():
    # source : https://stackoverflow.com/questions/52605094/python-argparse-increase-space-between-parameter-and-description
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)

    return formatter


def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(), prog='c2detective',
                                     description='Application for detecting command and control (C2) '
                                                 'communication through network traffic analysis.')

    parser.add_argument(
        '-q', '--quiet', help="do not print banner", action='store_true')

    update_group = parser.add_argument_group('required options')
    required_args = update_group.add_mutually_exclusive_group(required=True)
    required_args.add_argument('-i', '--input', metavar='FILENAME', help='input file (.cap / .pcap / .pcapng)')
    required_args.add_argument('-p', '--packet-capture', action='store_true',
                               help='start packet capture (setup in the configuration file)')

    parser.add_argument('-c', '--config', metavar='FILE', default="config/config.yml",
                        help="configuration file (default: 'config/config.yml')")
    parser.add_argument('-s', '--statistics', action='store_true',
                        help='print packet capture statistics to the console')
    parser.add_argument('-w', '--write-extracted', action='store_true',
                        help='write extracted data to a JSON file')
    parser.add_argument('-o', '--output', metavar='PATH', default="reports",
                        help="output directory file path for report files (default: 'reports/')")

    enable_group = parser.add_argument_group('enable options')
    enable_group.add_argument('-d', '--dga', action='store_true',
                              help="enable DGA domain detection")
    enable_group.add_argument('-g', '--plugins', action='store_true',
                              help="enable plugins for extended detection capabilities")
    enable_group.add_argument('-e', '--enrich-iocs', action='store_true',
                              help="enable data enrichment")

    update_group = parser.add_argument_group('update options')
    # update_group.add_argument('-utn', '--update-tor-nodes', action='store_true',
    #                           help='update tor node lists')
    # update_group.add_argument('-ucd', '--update-crypto-domains', action='store_true',
    #                           help='update crypto / cryptojacking based sites list')
    # update_group.add_argument('-ujr', '--update-ja3-rules', action='store_true',
    #                           help='update JA3 rules')

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/c2detective.log",
                        level=logging.DEBUG)  # consider json/yml format for log file
    logger = logging.getLogger('__name__')


def main():
    init_logger()
    is_platform_supported()

    analysis_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    args = parse_arguments()

    if not args.quiet:
        banner()

    terminal_size = os.get_terminal_size()

    print('-' * terminal_size.columns)
    if is_valid_file(args.config, "yml"):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading configuration file '{args.config}' ...")
        logging.info(f"Loading configuration file '{args.config}'")
        config = load_config(args.config)
        analyst_profile = AnalystProfile(config)

    print('-' * terminal_size.columns)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Verifying required directory structure ...")
    logging.info("Verifying required directory structure")
    output_dir = args.output
    check_required_structure(analyst_profile, output_dir)

    print('-' * terminal_size.columns)
    input_file = args.input

    if args.packet_capture:
        packet_capture = PacketCapture(analyst_profile.sniffing, output_dir)
        input_file = packet_capture.capture_packets()

    if is_valid_file(input_file, "log"):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading '{input_file}' input file ...")
        logging.info(f"Loading '{input_file}' input file")
        report_extracted_data_option = args.write_extracted
        statistics_option = args.statistics
        packet_parser = PacketParser(analysis_timestamp, analyst_profile, input_file, output_dir, report_extracted_data_option,
                                     statistics_option)
        extracted_data = packet_parser.get_extracted_data()

    plugins = None
    if args.plugins:
        print('-' * terminal_size.columns)
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading configured plugins ...")
        logging.info("Loading configured plugins")

        if analyst_profile.plugins:
            plugins = analyst_profile.plugins
            # NOTE: More plugins can be added in the future
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [WARNING] No plugins were added ...")
            logging.warning("No plugins were added")

    # set the total count of C2 indicators

    # without C2hunter = 11 ; 
    # without C2hunter and DGA (args.dga) = 10;    
    c2_indicators_total_count = 3
    print('-' * terminal_size.columns)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detection engine configuration ...")
    logging.info("Detection engine configuration")
    detection_engine = DetectionEngine(c2_indicators_total_count, analyst_profile, packet_parser)
    print(('- ' * (terminal_size.columns // 2)) + ('-' * (terminal_size.columns % 2)))
    detection_engine.detect_connections_with_excessive_frequency()

    if args.dga:
        detection_engine.detect_dga()
    
    
    with open('config/domain_whitelist.txt', 'r') as f:
        whitelist = set(line.strip() for line in f)

    # Open the input DNS log file and create an output file for non-whitelisted queries
    with open(input_file, 'r') as input_file, open('pcaps/non_whitelisted_queries.log', 'w') as output_file:
        for line in input_file:
            entry = json.loads(line)
            query = entry.get('query', '')
            domain = ".".join(query.split('.')[-2:])
            # Check if the query is not in the whitelist
            if domain not in whitelist:
                output_file.write(line)
    print(input_file)
    input_file.close()
    # os.remove(input_file.name)
    new_input_file = 'pcaps/non_whitelisted_queries.log'



    flow_analysis.clients_by_volume_of_requests(new_input_file)
    flow_analysis.analyze_dns_log_record_type(new_input_file)
    flow_analysis.analyze_packet_size_and_volume(new_input_file)
    flow_analysis.detect_beaconing_activity(new_input_file)
    flow_analysis.detect_hosts_talking_to_beaconing_domains(new_input_file)
    flow_analysis.detect_domains_with_lots_of_subdomains(new_input_file)
    flow_analysis.detect_dns_tunneling_based_on_entropy(new_input_file)

    detection_engine.detect_from_ml_model(new_input_file)
    detection_engine.detect_dns_tunneling()

    conn = sqlite3.connect('detection_logs.db')
    c = conn.cursor()

    # Create tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS excessive_frequency (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    ioc TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS long_subdomain (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    ioc TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS dns_tunneling_model (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    ioc TEXT
                )''')
    conn.commit()
    # conn.close()

    print("################################SCIRPT LOGS#####################################")
    if "excessive_frequency" in detection_engine.detected_iocs:
        conn = sqlite3.connect('detection_logs.db')
        c = conn.cursor()
        for ioc in detection_engine.detected_iocs["excessive_frequency"]:
            timestamp = time.strftime('%H:%M:%S')
            c.execute("INSERT INTO excessive_frequency (timestamp, ioc) VALUES (?, ?)", (timestamp, str(ioc)))
        conn.commit()
        # conn.close()

    # Check if "DNS_Tunneling" is in detected IOCs
    if "DNS_Tunneling" in detection_engine.detected_iocs:
        conn = sqlite3.connect('detection_logs.db')
        c = conn.cursor()
        for ioc in detection_engine.detected_iocs["DNS_Tunneling"]:
            timestamp = time.strftime('%H:%M:%S')
            c.execute("INSERT INTO long_subdomain (timestamp, ioc) VALUES (?, ?)", (timestamp, str(ioc)))
        conn.commit()
        # conn.close()
    print("#################################MODEL LOGS####################################")
    if "DNS_Tunneling_Model" in detection_engine.detected_iocs:
        conn = sqlite3.connect('detection_logs.db')
        c = conn.cursor()
        for ioc in detection_engine.detected_iocs["DNS_Tunneling_Model"]:
            timestamp = time.strftime('%H:%M:%S')
            c.execute("INSERT INTO dns_tunneling_model (timestamp, ioc) VALUES (?, ?)", (timestamp, str(ioc["query"])))
        conn.commit()
        conn.close()

    # if plugin_c2hunter:
    #     print(('- ' * (terminal_size.columns // 2)) + ('-' * (terminal_size.columns % 2)))
    #     c2hunter_db = plugins.get('C2Hunter')
    #     if os.path.isfile(c2hunter_db):
    #         print(f"[{time.strftime('%H:%M:%S')}] [INFO] Using plugin C2Hunter for enhanced detection capabilities ...")
    #         logging.info("Using plugin C2Hunter for enhanced detection capabilities")
    #         detection_engine.c2hunter_plugin(c2hunter_db)
    #     else:
    #         print(
    #             f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided C2Hunter database at '{c2hunter_db}' does not exist")
    #         logging.error(f"Provided C2Hunter database at '{c2hunter_db}' does not exist")

    detected_iocs = detection_engine.get_detected_iocs()

    if args.enrich_iocs:
        print('-' * terminal_size.columns)
        # using set() to remove duplicates and check for values count
        no_enabled_services = len(list(set(list(analyst_profile.enrichment_services.values())))) == 1
        # do not use enrichment services when all services are set to 'False' even if enrichment flas is enabled
        if no_enabled_services:
            print(
                f"[{time.strftime('%H:%M:%S')}] [WARNING] No enrichment services are enabled in the configuration file")
            logging.warning("No enrichment services are enabled in the configuration file")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] IoCs enrichment engine configuration ...")
            logging.info("IoCs enrichment engine configuration")
            enrichment_enchine = EnrichmentEngine(output_dir, analyst_profile.api_keys, analyst_profile.api_urls,
                                                  analyst_profile.enrichment_services, detected_iocs)
            enriched_iocs = enrichment_enchine.enrich_detected_iocs()
    else:
        enrichment_enchine = None
        enriched_iocs = {}

    print('-' * terminal_size.columns)
    detection_engine.evaluate_detection()

    print('-' * terminal_size.columns)
    if extracted_data and detected_iocs:
        c2_indicators_count = detection_engine.get_c2_indicators_count()
        thresholds = analyst_profile.thresholds
        detection_reporter = DetectionReporter(output_dir, thresholds, c2_indicators_total_count, c2_indicators_count,
                                               extracted_data, enriched_iocs,detected_iocs)
        detection_reporter.write_detected_iocs_to_file()
        if args.enrich_iocs:
            detection_reporter.write_enriched_iocs_to_file()
        detection_reporter.create_html_analysis_report()
        detection_reporter.write_extracted_data_to_file("dataframe_log")
    else:
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] The provided data is incomplete, therefore, exporting detected IoCs is not possible ...")
        logging.error(f"The provided data is incomplete, therefore, exporting detected IoCs is not possible")

    print('-' * terminal_size.columns)
    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...\n")
    logging.info("All done. Exiting program")


if __name__ == '__main__':
    main()
