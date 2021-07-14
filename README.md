# Overview
CertMonitor is a certificate expiration monitoring software. This software will help to eliminate costly outages when a certificate expires on critical applications. All configuration is setup through a simple to use YAML configuration file. The YAML file offers the ability for the program to continuously run and check on a schedule or individual runs that can be run with a different task scheduling software.

The program is currently setup to monitor SSL website certificates for expiration. In the future,  non-URL certificate expiration will get added.

## Program Highlights:
* The YAML file allows updating on the fly, and each loop will use the updated YAML configuration.
* Customizable certificate checks based on the sleep YAML setting (hourly, daily, weekly, monthly).
* Unlimited amount of SSL websites can get monitored.
* Email supports standard port 25 or TLS

## Setup Recommendations & Setup Hints:
The YAML file is broken into four main configuration sections. You will only need to edit the first three (general, site_urls, and notification_handler) for general usage. Each YAML section in the YAML file explains what each value represents. The fourth section is for logging, which is "INFO" level logging by default.

# Program Prerequisites:
Use the requirements.txt file to make sure you have all the required prerequisites. You should have "wheel" installed as well (pip install wheel). This helps cleanly get the latest version of Github libraries is the requirements.txt. This program will use an additional package called ictoolkit created by IncognitoCoding for most general function calls. Future programs will utilize the similar ictoolkit package. Feel free to use this package for your Python programming.

## How to Use:
The sample YAML configuration file has plenty of notes to help explain the setup process. The steps below will explain what needs to be done to get the program running with continuous monitoring enabled. You can use similar steps when continuous monitoring is disabled, but scheduled runs will need setup.

    Step 1: For the program to recognize the YAML file, you must copy the sample_certmonitor.yaml file and rename it to certmonitor.yaml 
    Step 2: Update the YAML file with your configuration. Also, eanble continuous_monitoring.
    Step 3: Run the program to make sure your settings are entered correctly. 
    Step 4: Depending on your operating system (Linux Ubuntu or Windows), you can set up the program to run automatically, which is recommended. Other Linux versions will work but are not explained below. 
       Step 4.1 (Optional - Windows): Setup a scheduled task to run the program on startup.
                Create a service account and a new scheduled task using these settings. A delayed start may be required.
                    - Run weather user is logged on or not
                    - Run with highest privileges
                    - Run hidden
                    - Set trigger time. Maybe daily around midnight
                    - Set action to start program
                    - Program/Script: python
                    - Arguments: "C:\<path to the program>\certmonitor.py"
       Step 4.2 (Optional - Linux Ubuntu): Set up a service to run the program.
            Step 4.2.1:  Create a new service file.
                Run: cd /lib/systemd/system
                Run: sudo nano certmonitor.service
                    Note1: The service account needs to have docker socket access. The root user is added below as an example.
                    Note2: A delayed start can help ensure all processes start before monitoring starts. Your "TimeoutStartSec" must be greater than the "ExecStartPre".
                    Paste:
                        Description=certmonitor
                        After=multi-user.target
                        After=network.target

                        [Service]
                        Type=simple
                        User=root
                        TimeoutStartSec=240
                        ExecStartPre=/bin/sleep 120
                        WorkingDirectory=/<path to program>/certmonitor
                        ExecStart=/usr/bin/python3  /<path to program>/certmonitor/certmonitor.py                                                         
                        Restart=no

                        [Install]
                        WantedBy=multi-user.target
            Step 4.2.2:  Create a new service file.
                Run: sudo systemctl daemon-reload
            Step 4.2.3: Enable the new service.
                sudo systemctl enable certmonitor.service
            Step 4.2.4: Start the new service.
                sudo systemctl start certmonitor.service
            Step 4.2.5: Check the status of the new service.
                sudo systemctl status certmonitor.service
    Step 5: Verify the program is running as a service or scheduled task. 
    Step 6: Once verified, you should set the logging handler to option 2 and the file's log level to INFO. This will cut down on disk space.
## Troubleshooting:
The YAML file offers logging DEBUG options to troubleshoot any issues you encounter. Please report any bugs.
#### Future Updates:
Offer the ability to check non-URL certificate expiration.
