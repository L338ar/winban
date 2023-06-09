
# WinBan

A python script to protect Windows system from brut-force attacks by blocking IP addresses that have made too many failed login attempts.

Originally  written as a quick RDP brute-force preventor, it is now a full Events->Firewall engine in the same spirit as [Fail2Ban](https://github.com/fail2ban/fail2ban)
## Warning
Please review the actual Python script before deploying in production. What works on my test machines may not work at yours. Like any other security system, you should run tests and verity it works!
## Installation

The script depends on two non built-in modules that needs to be installed:
|Module|use|
|---|---|
|pywin32|Provide access to Windows Events|
|schedule|Scheduling firewall rules|

You can install them using pip as below:
```cmd
  pip install schedule
  pip install pywin32
```

 Copy the script to any desired folder along with the config.ini file and run it:
 ``python3 winban.py``   
## How to use

For basic RDP protection, all you need is to run the script with the current configuration.
It will block any 3 attempts in a span of two hours for 24 hours.

### configuration
At the top of the script you will find 5 variables that will change the behaviour of the script.
|Variable|Default|Description|
|---|---|---|
|FailureTH|3|Failure threshold - How many failed logins from the same IP will trigger a block|
|FailureTime|120|Number of minutes the threshold should be checked.|
|BlockMinutes|1440|For how long each IP will be blocked after threshold (1440 = a day)|
|DeleteWhenExit|True|should Firewall rules be cleared on exit|
|WhiteList|['127.0.0.1','127.0.0.2']|A list of IPs that will not be blocked|

Changing the logging level from INFO to DEBUG will result much more data that usually is not needed. Changing it to ERROR will keep output to minimum.

For trapping custom events, please see next section about CONFIG.INI
## CONFIG.INI syntax

CONFIG.INI holds all the rules for trapping attacks. It basically tells the script what event to listen to and how to extract needed data (such as the IP address) from it.

Each section begins with the rule name between [...] and must have the following fields:
|Field name|Description|
|---|---|
|eventfilter|holds two segments, divided by PIPE (\|). First segment is the event log to listen to (Application/Security/etc). The second segment is the full query for the events.|
|ip|Also divided by a pipe, this field tells the script from where to extract the IP address, beginning the search with the first field and ending with the second. The script tries to find the IP address between those two segments.|

Additionally, you can add the following fields:
|Field name|Description|
|---|---|
|info|Same syntax as the ip field, the script can cut a part of the event and show it in the log. This can be anything and only effects the printed output.|
|detector|Additional keyword to filter the events in case the query is not detailed enough. The event will only trigger if the keyword is present.|

The default config.ini file comes with 3 services (well, 4 if you count the one for internal tests). Both RDP and OpenSSH use all the fields so feel free to learn from it.

## Clean-up

The script was designed to reset all changes to the host when exiting. While the script runs it creates/use a firewall rule named "RDP-BF-GUARD<n>" (this can be changed via the rule_name variable). If the script is closed unexpectedly, manually removing the rule will restore the system to regular functionality (and vulnerability).

## License

[MIT](https://choosealicense.com/licenses/mit/)


## Contributing

Contributions are always welcome!
If you added a service to the config.ini file please share so others can enjoy as well.

## Author

- [@l338ar](https://github.com/L338ar)

