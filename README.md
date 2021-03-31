**FMC ACP Double logging detection and mitigation script**

A python based script to generate report if there are double logging on FMC ACP (logging at begining and end), having rule action "Allow" or "Trust"

The usage is as below.
Ensure python3 is installed and the below modules are already available 
Both the python files "logging_main_1.9.py" and "rule_writer.py" is needed.

1. Enter the IP of the FMC
2. Username and password (Make use of a separate user for running API based script on FMC)
3. Select the ACP you want to detect double logging.
4. You can either choose to just generate the report or 
5. Generate report along with changing the logging  to end of connection and save the changes. 

```
        PS C:\Users\anupam\Desktop\scripts\Logging-Bulk-beg-end\Release\loggin_main_1.9.py> python logging_main_1.9.py
        ###########################################################
        #               ACCESS CONTROL POLICY                     #
        ###########################################################
        #         anpavith              Cisco Systems India       #
        ###########################################################
        Enter the device IP address  : 10.106.55.55
        Enter the username of the FMC: api
        Enter the password of the FMC:
        ###########################################################
        #             ACCESS CONTROL POLICY LIST                  #
        ###########################################################
        1 5585-SFR
        2 Blank Policy
        3 Copy of Delhi Shared
        4 FTD-Mig-ACP-1613142830
        5 FTD-Mig-ACP-1615773808
        6 HELIUM
        7 BACKUP-SERVER-FW
        8 SERVER-FW-BACKBONE
        9 M_FW01-Updated
        ###########################################################
        Choose the ACP Number (integer value):8
        ###########################################################
                        Available operations on ACP
        ###########################################################
        1. Report rules with Action = Allow, LogBeg & LogEnd
        2. Disable logging at Beg if Allow, LogBeg & LogEnd
        ###########################################################
        Enter your selection (integer value) : 1
        ###########################################################
        Processing, Please Wait
        >>>>>>>>
        Retrived all rules from  SERVER-FW-BACKBONE
        ###########################################################
        Total number of rules in Access Control Policy      :  7965
        Number of rules with Allow action & LogBeg & LogEnd :  985
        The report has been created with name  ACP_SERVER-FW-BACKBONE_Report_1617188521.9678984.csv
        ###########################################################
```
