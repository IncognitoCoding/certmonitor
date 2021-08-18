# Built-in/Generic Imports
import os
import sys
import logging
import time
from urllib.request import  ssl, socket
import datetime
import traceback

# Own modules
from ictoolkit.directors.yaml_director import read_yaml_config, yaml_value_validation
from ictoolkit.directors.log_director import setup_logger_yaml
from ictoolkit.directors.email_director import send_email

__author__ = 'IncognitoCoding'
__copyright__ = 'Copyright 2021, CertMonitor'
__credits__ = ['IncognitoCoding']
__license__ = 'GPL'
__version__ = '0.3'
__maintainer__ = 'IncognitoCoding'
__status__ = 'Development'

class SSL_Check(object):

    def ssl_pull(self, site_url):
        """
        Pulls the SSL website certificate expiration date.

        Args:
            site_url (str): The URL to the website.
                \- site_url Example: 'mywebsite.com'

        Returns:
            object: Returns all pieces of the URL certificate in object format.
        """
        logger = logging.getLogger(__name__)

        context = ssl.create_default_context()
        try:

            with socket.create_connection((site_url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=site_url) as ssock:
                    logger.debug('Getting the SSL certificate information from the site_url')
                    # Gets SSL certificate information from the site_url.
                    ssl_info = ssock.getpeercert()
                    logger.debug(f'SSL certificate info = {ssl_info}')
                    # Returns the certificiate information in object format.
                    # Output Example: {'subject': ((('countryName', 'US'),), (('stateOrProvinceName', 'IL'),), (('localityName', 'Washington'),), (('organizationName', 'TI'),), 
                    #                             (('organizationalUnitName', 'TI'),), (('commonName', 'ti-esxi-host2.ad.thoroughinnovations.com'),)), 
                    #                  'issuer': ((('domainComponent', 'com'),), (('domainComponent', 'thoroughinnovations'),), (('domainComponent', 'ad'),), (('commonName', 'Thorough Innovations Sub CA'),)), 
                    #                  'version': 3, 'serialNumber': '500000001D3495FD8D0135CB7E00010000001D', 
                    #                  'notBefore': 'Jul 13 15:59:44 2021 GMT', 
                    #                  'notAfter': 'Jul 13 15:59:44 2022 GMT', 
                    #                  'subjectAltName': (('DNS', 'ti-esxi-host2.ad.thoroughinnovations.com'), ('DNS', 'ti-esxi-host2'), ('IP Address', '10.10.200.96')), 
                    #                  'OCSP': ('http://ocsp.ad.thoroughinnovations.com/ocsp',), 
                    #                  'caIssuers': ('ldap:///CN=Thorough%20Innovations%20Sub%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ad,DC=thoroughinnovations,
                    #                                 DC=com?cACertificate?base?objectClass=certificationAuthority',), 
                    #                  'crlDistributionPoints': ('ldap:///CN=Thorough%20Innovations%20Sub%20CA,CN=TI-Cert1,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ad,
                    #                                            DC=thoroughinnovations,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint', 'http://pki.ad.thoroughinnovations.com/CertEnroll/Thorough%20Innovations%20Sub%20CA.crl')}
                    self.subject = ssl_info.get('subject')
                    self.issuer = ssl_info.get('issuer')
                    self.version = ssl_info.get('version')
                    self.notBefore = ssl_info.get('notBefore')
                    self.notAfter = ssl_info.get('notAfter')
                    self.subjectAltName = ssl_info.get('subjectAltName')
                    self.OCSP = ssl_info.get('OCSP')
                    self.caIssuers = ssl_info.get('caIssuers')
                    self.crlDistributionPoints = ssl_info.get('crlDistributionPoints')
            logger.debug('Returning the SSL certificate value objects')
            return self
        except Exception as err:
            if 'EOF occurred in violation of protocol' in str(err):
                error_message = (
                    f'A failure occurred while getting SSL information for {site_url}.\n' +
                    (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                    'Error Output:\n'
                    f'  - {err}\n\n'
                    'Suggested Resolution:\n'
                    f'  - Please validate that the website is an HTTPS supported website.\n\n'
                    f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                    (('-' * 150) + '\n') * 2 
                )   
                raise ValueError(error_message)
            elif 'getaddrinfo failed' in str(err):
                error_message = (
                    f'A failure occurred while getting SSL information for {site_url}.\n' +
                    (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                    'Error Output:\n'
                    f'  - {err}\n\n'
                    'Suggested Resolution:\n'
                    f'  - Please validate that the website address is reachable.\n\n'
                    f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                    (('-' * 150) + '\n') * 2 
                )   
                raise ValueError(error_message)
            else:
                error_message = (
                    f'A failure occurred while getting SSL information for {site_url}.\n' +
                    (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                    'Error Output:\n'
                    f'  - {err}\n\n'
                    f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                    (('-' * 150) + '\n') * 2 
                )   
                raise ValueError(error_message)


class URL_Info(object):

    def get_url_certificate_info(self, site_url, buffer_days, time_zone):
        """.
        Gets SSL details from the URL and calculates if the certificate is expiring. Alerts are triggered based on the buffer_days.

        Args:
            site_url (str): A website URL.
            buffer_days (int): Days to buffer certificate expiring before notifying.
            time_zone (str): Time zone the program is running. The time zone is used for cleaner logging. If your time zone is not listed, choose any and convert log output manually.
                \- time_zone Options: CST, UTC, EST, MST, or PST

        Raises:
            ValueError: Raised errors from SSL_Check class.
            ValueError: An incorrect time zone format was sent.
            ValueError: A general error has occurred while calculating the certificate expiration day for <site_url>.

        Returns:
            str: The certificate expiration status message.
        """
        logger = logging.getLogger(__name__)
        try:
            logger.debug(f'Checking site {site_url} for SSL information')
            # Strips https if it exists.
            site_url = site_url.replace('https://','')
            # Calls class and makes call to pull ssl.
            ssl_check = SSL_Check()
            ssl_output = ssl_check.ssl_pull(site_url)
        except Exception as err:
            raise ValueError(err)
        
        try:

            ##########################################################
            #######Sets The Date Format Based On Running Timezone#####
            ##########################################################
            logger.debug('Setting the date format based on the running time zone')
            if 'cst' == time_zone or 'CST' == time_zone:
                date_format = '%a, %d %b %Y %H:%M:%S CST'
            elif 'utc' == time_zone or 'UTC' == time_zone:
                date_format = '%a, %d %b %Y %H:%M:%S UTC'
            elif 'est' == time_zone or 'EST' == time_zone:
                date_format = '%a, %d %b %Y %H:%M:%S EST'
            elif 'mst' == time_zone or 'MST' == time_zone:
                date_format = '%a, %d %b %Y %H:%M:%S MST'
            elif 'pst' == time_zone or 'PST' == time_zone:
                date_format = '%a, %d %b %Y %H:%M:%S PST'
            else:
                error_message = (
                    f'An incorrect time zone format was sent.\n' +
                    (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                    'Suggested Resolution:\n'
                    f'  - Please verify you entered the correct timezone abbreviation. Currently supported timezones are CST, UTC, EST, MST, and PST.\n\n'
                    f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                    (('-' * 150) + '\n') * 2 
                )   
                raise ValueError(error_message)
            logger.debug(f'Time zone is \'{time_zone}\'. date_format set to \'{date_format}\'')

            ##########################################################
            ###########Sets Expiration Date From SSL Output###########
            ##########################################################
            logger.debug('Setting the expiration date from SSL output')
            # Converts the certificate date from the class to an easily compareable format and sets to central time.
            ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
            # Gets the raw certificate expiration date from the class.
            certificate_expiration = ssl_output.notAfter
            # Gets the certral certificate expriation using the customized format.
            certificate_expiration1 = (datetime.datetime.strptime(certificate_expiration, ssl_date_fmt)).strftime(date_format)
            # Converts the string formatted expiration date back into a string parse time. Required for comparison.
            certificate_expiration = datetime.datetime.strptime(certificate_expiration1, date_format)
            logger.debug(f'Certificate expiration date is {certificate_expiration}')

            #############################################
            ################Sets Current Date############
            #############################################
            logger.debug('Setting the current date')
            # Sets the current date with central format
            current_datetime1 = datetime.datetime.now(datetime.timezone.utc).strftime(date_format)
            # Converts the string formatted date back into a string parse time. Required for comparison.
            current_datetime = datetime.datetime.strptime(current_datetime1, date_format)
            logger.debug(f'Current date is {current_datetime}')

            logger.debug('Calculating how many days remain before the certificate expires')
            # Gets how many days remain before the certificate expires.
            expiration_days_away = (certificate_expiration - current_datetime).days
            logger.debug(f'Expiration days away is {expiration_days_away}')
            # Checks if the certificate expiration showing the day it expires.
            if expiration_days_away == 0:
                logger.debug(f'Returning the expiration status message. Message = Warning: Certificate for {site_url} is expiring soon. The certificate will expire tomorrow')
                #return f'Warning: Certificate for {site_url} is expring soon. The certificate will expire tomorrow.'
                self.status_message = f'Warning: Certificate for {site_url} is expring soon. The certificate will expire tomorrow.'
                self.expiration_days_away = 0
                return self
            # Checks if the certificate expiration date has been met.
            elif expiration_days_away < 0:
                # Removes the negative sign.
                days_expired = str(expiration_days_away).replace('-','')
                logger.debug(f'Returning the expiration status message. Message = Error: Certificate for {site_url} has expired! The certificate has been expired for {days_expired} days.')
                #return f'Error: Certificate for {site_url} has expired! The certificate has been expired for {days_expired} days.'
                self.status_message = f'Error: Certificate for {site_url} has expired! The certificate has been expired for {days_expired} days.'
                self.expiration_days_away = -days_expired
                return self
            # Checks if the expiration days away has reached the buffer alert days.
            elif expiration_days_away <= buffer_days:
                logger.debug(f'Returning the expiration status message. Message = Warning: Certificate for {site_url} is expring soon. The certificate will expire in {expiration_days_away} days.')
                #return f'Warning: Certificate for {site_url} is expring soon. The certificate will expire in {expiration_days_away} days.'
                self.status_message = f'Warning: Certificate for {site_url} is expring soon. The certificate will expire in {expiration_days_away} days.'
                self.expiration_days_away = expiration_days_away
                return self
            else:
                logger.debug(f'Returning the expiration status message. Message = Info: Certificate for {site_url} is good. The certificate does not expire for {expiration_days_away} days.')
                #return f'Info: Certificate for {site_url} is good. The certificate does not expire for {expiration_days_away} days.'
                self.status_message = f'Info: Certificate for {site_url} is good. The certificate does not expire for {expiration_days_away} days.'
                self.expiration_days_away = expiration_days_away
                return self
        except Exception as err:
            error_message = (
                f'A general error has occurred while calculating the certificate expiration day for {site_url}.\n' +
                (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                'Error Output:\n'
                f'  - {err}\n\n'
                'Suggested Resolution:\n'
                f'  - Please report this error to the developer.\n\n'
                f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                (('-' * 150) + '\n') * 2 
            )   
            raise ValueError(error_message)


class Startup_Variables(object):

    def populate_startup_variables(self):
        """
        This function populates all hard-coded and yaml-configuration variables into a dictionary that is pulled into the main function.
        YAML entry validation checks are performed within this function. No manual configurations are setup within the program. All user 
        settings are completed in the "certmonitor.yaml" configuration file.
        
        Raises:
            ValueError: NameError
            ValueError: KeyError
            ValueError: General Error
            
        Returns:
            objects: Objects of all startup variables required for the program to run. These startup variables consist of pre-configured and YAML configuration.
        """
        logger = logging.getLogger(__name__)

        # Initialized an empty dictionary for email variables.
        email_settings = {}

        # This is required to start the program. The YAML file is read to set the required variables.
        # No file output or formatted console logging is completed in these variable population sections. Basic print statements will prompt an error.
        # Each configuration section is unique. To make the read easier, each sections will be comment blocked using ############.
        try:

            # Sets root directory.
            preset_root_directory = os.path.dirname(os.path.realpath(__file__))
            # Sets the YAML file configuration location.
            yaml_file_path = os.path.abspath(f'{preset_root_directory}/certmonitor.yaml')
            # Calls function to setup the logging configuration with the YAML file.
            setup_logger_yaml(yaml_file_path)
            # Sets up the logger.
            logger = logging.getLogger(__name__)
            logger.debug('Loading YAML configuration values')
            # Gets the config from the YAML file.
            returned_yaml_read_config = read_yaml_config(yaml_file_path, 'SafeLoader')
            # Sets the yaml read configuration to the dictionary.
            self.imported_yaml_read_config = returned_yaml_read_config
            
            # Gets the continuous_monitoring option to allow looping.
            # Time is in seconds.
            continuous_monitoring = returned_yaml_read_config.get('general').get('continuous_monitoring')
            # Validates the YAML value.
            yaml_value_validation('continuous_monitoring', continuous_monitoring, bool) 
            # Sets the continuous_monitoring option as an object.
            self.continuous_monitoring = continuous_monitoring

            # Gets the monitoring software sleep settings.
            # Time is in seconds.
            monitor_sleep = returned_yaml_read_config.get('general').get('monitor_sleep')
            # Validates the YAML value.
            yaml_value_validation('monitor_sleep', monitor_sleep, int) 
            # Sets the sleep time in seconds as an object.
            self.monitor_sleep = monitor_sleep

            # Gets the option to enable or not enable email alerts.
            email_alerts = returned_yaml_read_config.get('general').get('email_alerts')
            # Validates the YAML value.
            yaml_value_validation('email_alerts', email_alerts, bool)
            # Sets the sleep time in seconds as an object.
            self.email_alerts = email_alerts

            # Gets the option to enable or not enable program error email alerts.
            alert_program_errors = returned_yaml_read_config.get('general').get('alert_program_errors')
            # Validates the YAML value.
            yaml_value_validation('alert_program_errors', alert_program_errors, bool)
            # Sets the sleep time in seconds as an object.
            self.alert_program_errors = alert_program_errors

            # Gets the option to set the buffer days before certificate warnings start.
            buffer_days = returned_yaml_read_config.get('general').get('buffer_days')
            # Validates the YAML value.
            yaml_value_validation('buffer_days', buffer_days, int)
            # Sets the buffer days as an object.
            self.buffer_days = buffer_days

            # Gets the option to set the time_zome.
            time_zome = returned_yaml_read_config.get('general').get('time_zome')
            # Validates the YAML value.
            yaml_value_validation('time_zome', time_zome, str)
            # Sets the time zone as an object.
            self.time_zome = time_zome

            # Gets the URLs to check the certificate.
            # Validates the YAML value.
            for url in returned_yaml_read_config.get('site_urls'):
                # Validates the YAML value.
                yaml_value_validation('site_url list entry', url, str)
            # Sets the url list as an object.
            self.urls = list(returned_yaml_read_config.get('site_urls'))

            # Sets email values.
            smtp = returned_yaml_read_config.get('notification_handler').get('email').get('smtp')
            authentication_required = returned_yaml_read_config.get('notification_handler').get('email').get('authentication_required')
            use_tls = returned_yaml_read_config.get('notification_handler').get('email').get('use_tls')
            username = returned_yaml_read_config.get('notification_handler').get('email').get('username')
            password = returned_yaml_read_config.get('notification_handler').get('email').get('password')
            from_email = returned_yaml_read_config.get('notification_handler').get('email').get('from_email')
            to_email = returned_yaml_read_config.get('notification_handler').get('email').get('to_email')
            # Validates the YAML value.
            yaml_value_validation('smtp', smtp, str)
            yaml_value_validation('authentication_required', authentication_required, bool)
            yaml_value_validation('use_tls', use_tls, bool)
            yaml_value_validation('username', username, str)
            yaml_value_validation('password', password, str)
            yaml_value_validation('from_email', from_email, str)
            yaml_value_validation('to_email', to_email, str)
            # Adds the email_settings into a dictionary.
            # This format is required for the email function parameters.
            email_settings['smtp'] = smtp
            email_settings['authentication_required'] = authentication_required
            email_settings['use_tls'] = use_tls
            email_settings['username'] = username
            email_settings['password'] = password
            email_settings['from_email'] = from_email
            email_settings['to_email'] = to_email
            # Sets email dictionary settings as an object.
            self.email_settings = email_settings
            logger.debug('Returning YAML configuration value objects')
            # Returns the dictionary with all the startup variables.
            return self
        except NameError as err:
            print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|NameError: {err} Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')

        except KeyError as err:
            print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|KeyError: {err} Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')
            
        except Exception as err:
            print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|{err} Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')
            quit()

    
def main():

    while True:
        logger = logging.getLogger(__name__)
        # Initiates class.
        startup_variables = Startup_Variables()
        # Calls function to pull in the startup variables.
        predefined_variables = startup_variables.populate_startup_variables()

        logger.info('#' * 80)
        logger.info(' ' * 34 + 'CertMonitor' + ' ' * 35)
        logger.info('#' * 80)

        # Override created to change user defined sleep if a certificate expires within the time the program would sleep.
        # This will reset each loop and if a certificate expires within the sleep the override will be enabled and the program will loop every 24 hours.
        # For example: Alerts for certificates expring set at 15 days, but the program sleeps 30 days.
        override_sleep_seconds = None

        # Loops through each URL.
        for url in predefined_variables.urls:

            try:
                
                url_info = URL_Info()
                # Gets the certificate info status.
                url_certificate_output = url_info.get_url_certificate_info(url, predefined_variables.buffer_days, predefined_variables.time_zome)
                # Checks return output for specific strings to create email specific messages.
                # The return output will contain "Info:, Warning:, or Error:" when returning.
                if 'Warning:' in str(url_certificate_output.status_message):
                    subject = 'Website Certificate Expiring Soon'
                    # Removes the warning part at the beginning of the return output.
                    body = str(url_certificate_output.status_message).replace('Warning: ','')
                    logger.warning(body)
                    # Calls function to send the email.
                    # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                    send_email(predefined_variables.email_settings, subject, body)  
                    if override_sleep_seconds:
                        logger.info('24-hour sleep override is already set from the previous certificate check')
                    elif not override_sleep_seconds:
                        # Sets the sleep override because the certificate expires soon. The override will override the user's pre-defined sleep and change the sleep to only sleep for 24 hours.
                        override_sleep_seconds = 86400
                        logger.info('Setting sleep override to 24 hour because the certificate expires soon')
                elif 'Error:' in str(url_certificate_output.status_message):
                    subject = 'Website Certificate Expired'
                    # Removes the warning part at the beginning of the return output.
                    body = str(url_certificate_output.status_message).replace('Error: ','')
                    logger.error(body)
                    # Calls function to send the email.
                    # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                    send_email(predefined_variables.email_settings, subject, body) 
                    if override_sleep_seconds:
                        logger.info('24-hour sleep override is already set from the previous certificate check')
                    elif not override_sleep_seconds:
                        # Sets the sleep override because the certificate expired. The override will override the user's pre-defined sleep and change the sleep to only sleep for 24 hours.
                        override_sleep_seconds = 86400
                        logger.info('Setting sleep override to 24 hour because the certificate expired')
                elif 'Info:' in str(url_certificate_output.status_message):
                    # Checks if the program should continue to loop and sleep based on the "monitoring_sleep" value and no sleep override has been set from a different certificate expring.
                    # A certificate expiring or expired will override at 24 hours, which will be a quicker then the time delta below.
                    if predefined_variables.continuous_monitoring and not override_sleep_seconds:
                        # Converts seconds to full time output for clean log output.
                        sleep_time = datetime.timedelta(seconds=predefined_variables.monitor_sleep)
                        # Checks if the sleep days exceeds the certificates expiration date to set override.
                        if sleep_time.days >= url_certificate_output.expiration_days_away:
                            # Gets the amount of days between the sleep time and certificate expiration.
                            sleep_time_to_expiration_delta = sleep_time.days - url_certificate_output.expiration_days_away
                            logger.info(f'The user-defined sleep exceeds the certificate expiration. Enabling override to {sleep_time_to_expiration_delta} seconds.') 
                            override_sleep_seconds = sleep_time_to_expiration_delta
                    logger.info(str(url_certificate_output.status_message).replace('Info: ',''))
                else:
                    # Checks if program error alerts should be emailed.
                    if predefined_variables.alert_program_errors:
                        subject = 'certmonitor failed to validate returned SSL check'
                        body = f'The URL ({url}) failed to be checked because certmonitor failed to validate returned SSL check value. Return value = {url_certificate_output.status_message}'
                        # Calls function to send the email.
                        # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                        send_email(predefined_variables.email_settings, subject, body) 

                        error_message = (
                            f'CertMonitor failed to validate returned SSL check for URL {url}.\n' +
                            (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                            'Error Output:\n'
                            f'  - Return status = {url_certificate_output.status_message}\n\n'
                            'Suggested Resolution:\n'
                            f'  - Please report this error to the developer.\n\n'
                            f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                            (('-' * 150) + '\n') * 2 
                        )   
                        logger.error(error_message) 
                        
                    else:
                        error_message = (
                            f'CertMonitor failed to validate returned SSL check for URL {url}.\n' +
                            (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                            'Error Output:\n'
                            f'  - Return status = {url_certificate_output.status_message}\n\n'
                            'Suggested Resolution:\n'
                            f'  - Please report this error to the developer.\n\n'
                            f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                            (('-' * 150) + '\n') * 2 
                        )   
                        logger.error(error_message) 
            except Exception as err:
                # Try catches are generally not inside an exception, but this exception is required because sending_email could have failures.
                try:

                    # Checks for error specifics for notification.
                    if 'Please validate that the website is an HTTPS supported website' in str(err):
                        # Checks if program error alerts should be emailed.
                        if predefined_variables.alert_program_errors:
                            subject = 'Website Certificate Validation Skipped'
                            body = f'The URL ({url}) is not reachable. This website may be offline or decommissioned. If the website is no longer available,'
                            ' you will want to remove this URL from the configuration file to avoid these alerts from continuing.'
                            # Calls function to send the email.
                            # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                            send_email(predefined_variables.email_settings, subject, body) 

                        error_message = (
                            f'Website Certificate Validation Skipped.\n' +
                            (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                            'Error Output:\n'
                            f'  - The URL ({url}) is not reachable. This website may be offline or decommissioned.\n\n'
                            'Suggested Resolution:\n'
                            f'  - If the website is no longer available, you will want to remove this URL from the configuration file to avoid these alerts from continuing.\n\n'
                            f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                            (('-' * 150) + '\n') * 2 
                        )   
                        logger.error(error_message) 
                    else:
                        # Checks if program error alerts should be emailed and that the program is not returning from an error from sending an email.
                        if predefined_variables.alert_program_errors and 'Failed to send the email message' not in str(err):
                            subject = 'Website Certificate Validation Skipped'
                            body = f'The URL ({url}) is being skipped because of a general error. See log for more details.'
                            # Calls function to send the email.
                            # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                            send_email(predefined_variables.email_settings, subject, body) 

                        # Checks if return errors are from IncogitoCoding returns. All IC returns will have already logged at the raised error.
                        if '-----------------Additional Information-----------------------' in str(err):
                            # Outputs raised error from original exception.
                            logger.error(err)
                            logger.error(f'Error end point on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
                            exit()
                        # Outputs any other non-IncogitoCoding captured error.
                        else:
                            logger.error(err)
                            logger.error(f'Error end point on line {traceback.extract_stack()[-1].lineno} in <{__name__}>') 
                            exit()
                except Exception as err:
                    # Checks if return errors are from IncogitoCoding returns. All IC returns will have already logged at the raised error.
                    if '-----------------Additional Information-----------------------' in str(err):
                        # Outputs raised error from original exception.
                        logger.error(err)
                        logger.error(f'Error end point on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
                        exit()
                    # Outputs any other non-IncogitoCoding captured error.
                    else:
                        logger.error(err) 
                        logger.error(f'Error end point on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
                        exit()
        # Checks if the program should continue to loop and sleep based on the "monitoring_sleep" value.
        if predefined_variables.continuous_monitoring:
            try:
                # Checks if sleep override has been set by the program.
                # Override is only enabled if the user sets a sleep larger than the expiration alert threshold or the expriation date is within the alert threshold.
                if override_sleep_seconds:
                    # Sets seconds in days.
                    seconds_in_day = 60 * 60 * 24
                    # Gets how many days are in the sleep seconds.
                    override_days = override_sleep_seconds // seconds_in_day
                    logger.info(f'The program has continuous monitoring enabled, and the override time has been set to alert every {override_sleep_seconds} seconds [{override_days} day(s)] because a certificate is expiring or is expired')
                    # Sleeps for adjusted override.
                    time.sleep(override_sleep_seconds)
                else:
                    # Converts seconds to full time output for clean log output.
                    sleep_time = datetime.timedelta(seconds=predefined_variables.monitor_sleep)
                    logger.info(f'The program has continuous monitoring enabled. Waiting {sleep_time} until next check')
                    # Sleeps based on the monitor sleep seconds entry.
                    time.sleep(predefined_variables.monitor_sleep)
            except Exception as err:
                error_message = (
                    f'An error has occurred while putting the program to sleep.\n' +
                    (('-' * 150) + '\n') + (('-' * 65) + 'Additional Information' + ('-' * 63) + '\n') + (('-' * 150) + '\n') +
                    'Error Output:\n'
                    f'  - {err}\n\n'
                    'Suggested Resolution:\n'
                    f'  - Please make sure your time is not set past \'49 days, 17:02:47\' or 4,294,968 seconds.\n\n'
                    f'Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>\n' +
                    (('-' * 150) + '\n') * 2 
                )   
                logger.error(error_message) 
                exit()
        else:
            logger.info(f'Website SSL validation check has completed')
            # Exits because the program is a single run.
            exit()


# Checks that this is the main program initiates the classes to start the functions.
if __name__ == "__main__":

    # Prints out at the start of the program.
    print('# ' + '=' * 85)
    print('Author: ' + __author__)
    print('Copyright: ' + __copyright__)
    print('Credits: ' + ', '.join(__credits__))
    print('License: ' + __license__)
    print('Version: ' + __version__)
    print('Maintainer: ' + __maintainer__)
    print('Status: ' + __status__)
    print('# ' + '=' * 85)

    # Calls main function.
    main()