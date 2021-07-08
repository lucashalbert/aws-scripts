# Description
This script validates a list of IPs, CIDRs, and ranges provided via a file or manually specified list on the command line. The script parses the list of IPs, CIDRs, and ranges and proceeds to validate, format, and check whether are any WAF updates necessary.

## Options and Arguments
The script takes a number of required and optional Options and Arguments.

|Option|Argument|Required?|
|---|---|---|
|`-h`|No argument required|==Optional==, Displays Help/Usage|
|`-f/--filename`|A file path|==Required== if `-l/--ip-list` is not provided|
|`-l/--ip-list`|A comma separated list of IPs, CIDRs, and/or ranges|==Required== if `-f/--filename` is not provided|
|`-ii/--ipset-id`|The ID of the WAF IPSet that is being worked on|==Optional==, the script will not check each entry against the existing IPSet if not provided|
|`--ct/--change-token`|A change token fetched via the command `aws waf-regional get-change-token --region ${region}` |==Optional==, used only in formatting the AWS CLI waf-regional update command|
|`-r/--region`|The AWS region that the WAF IPSet resides in|==Optional*==, unless the `-ii/--ipset-id` or `-ct/--change-token` options are specified|
|`-n/--dry-run`|No argument required|==Optional==, Does not attempt to check if entries exist in specified IPSet|


# OS and Python Environment Setup
* Python 3.8.10

Install `python3-venv` using OS package manager

## Python Virtual Environment set up
Create `python-envs` directory to hold python virtual environments
Run ` mkdir ~/python-envs/ && cd ~/python-envs/`

Create the ==waf== python virtual environment
Run `python3 -m venv waf`

## Activate the newly created virtual environment
Run `. ~/python-envs/waf/bin/activate`

## Update the virtual environment and install requirements
Run `pip install -U pip`
Run `pip install -r requirements.txt`

## Use ==gimme-aws-creds== to fetch an Okta session token
gimme-aws-creds is installed via the requirements.txt file, however, you will have to configure it to use the correct Okta endpoint

## Run the python `update_aws_waf.py` using a file containing the IPs, CIDRs, and ranges
Run `python update_aws_waf.py -f /tmp/ip_ranges.txt -ii 1751862a-4ee8-44e0-af0f-f69ca8e8bb69 -r us-west-2 -ct 4f1dca65-c2cb-4307-b9fb-38427ca644f7`
```
204.29.77.64/26          : String is a valid IPv4 network. The string '204.29.77.64/26' exists within the specified list
24.38.143.45/32          : String is a valid IPv4 network. The string '24.38.143.45/32' exists within the specified list
24.38.143.42/32          : String is a valid IPv4 network. The string '24.38.143.42/32' does NOT exist within the specified list
24.38.143.41             : String is a valid IPv4 network. The string '24.38.143.41' does NOT exist within the specified list
10.11.12.13-10.11.13.2   : Provided IP range is valid. - True  --  [IPv4Network('10.11.12.13/32'), IPv4Network('10.11.12.14/31'), IPv4Network('10.11.12.16/28'), IPv4Network('10.11.12.32/27'), IPv4Network('10.11.12.64/26'), IPv4Network('10.11.12.128/25'), IPv4Network('10.11.13.0/31'), IPv4Network('10.11.13.2/32')]
10.11.12.13/32           : String is a valid IPv4 network. The string '10.11.12.13/32' does NOT exist within the specified list
10.11.12.14/31           : String is a valid IPv4 network. The string '10.11.12.14/31' does NOT exist within the specified list
10.11.12.16/28           : String is a valid IPv4 network. The string '10.11.12.16/28' does NOT exist within the specified list
10.11.12.32/27           : String is a valid IPv4 network. The string '10.11.12.32/27' does NOT exist within the specified list
10.11.12.64/26           : String is a valid IPv4 network. The string '10.11.12.64/26' does NOT exist within the specified list
10.11.12.128/25          : String is a valid IPv4 network. The string '10.11.12.128/25' does NOT exist within the specified list
10.11.13.0/31            : String is a valid IPv4 network. The string '10.11.13.0/31' does NOT exist within the specified list
10.11.13.2/32            : String is a valid IPv4 network. The string '10.11.13.2/32' does NOT exist within the specified list

Number of updates to WAF: 10

Update WAF IP set list via the following command:
aws waf-regional update-ip-set --region us-west-2 --ip-set-id 0a52dc3d-a2a9-4f18-8c04-27625833d74c --change-token 28a27a7f-0402-4cf7-b90d-a2ffda3cfd1e --updates Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="24.38.143.42/32"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="24.38.143.41/32"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.13/32"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.14/31"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.16/28"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.32/27"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.64/26"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.128/25"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.13.0/31"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.13.2/32"}'
```


## Run the python `update_aws_waf.py` using a manual list containing the IPs, CIDRs, and ranges in a comma separated string format
Run `python update_aws_waf.py -l "10.11.12.13, 11.12.13.14,12.13.14.15, 13.14.15.16-15.16.17.18" -ii 1751862a-4ee8-44e0-af0f-f69ca8e8bb69 -r us-west-2 -ct 4f1dca65-c2cb-4307-b9fb-38427ca644f7`
```
10.11.12.13              : String is a valid IPv4 network. The string '10.11.12.13' does NOT exist within the specified list
11.12.13.14              : String is a valid IPv4 network. The string '11.12.13.14' does NOT exist within the specified list
12.13.14.15              : String is a valid IPv4 network. The string '12.13.14.15' does NOT exist within the specified list
13.14.15.16-15.16.17.18  : Provided IP range is valid. - True  --  [IPv4Network('13.14.15.16/28'), IPv4Network('13.14.15.32/27'), IPv4Network('13.14.15.64/26'), IPv4Network('13.14.15.128/25'), IPv4Network('13.14.16.0/20'), IPv4Network('13.14.32.0/19'), IPv4Network('13.14.64.0/18'), IPv4Network('13.14.128.0/17'), IPv4Network('13.15.0.0/16'), IPv4Network('13.16.0.0/12'), IPv4Network('13.32.0.0/11'), IPv4Network('13.64.0.0/10'), IPv4Network('13.128.0.0/9'), IPv4Network('14.0.0.0/8'), IPv4Network('15.0.0.0/12'), IPv4Network('15.16.0.0/20'), IPv4Network('15.16.16.0/24'), IPv4Network('15.16.17.0/28'), IPv4Network('15.16.17.16/31'), IPv4Network('15.16.17.18/32')]
13.14.15.16/28           : String is a valid IPv4 network. The string '13.14.15.16/28' does NOT exist within the specified list
13.14.15.32/27           : String is a valid IPv4 network. The string '13.14.15.32/27' does NOT exist within the specified list
13.14.15.64/26           : String is a valid IPv4 network. The string '13.14.15.64/26' does NOT exist within the specified list
13.14.15.128/25          : String is a valid IPv4 network. The string '13.14.15.128/25' does NOT exist within the specified list
13.14.16.0/20            : String is a valid IPv4 network. The string '13.14.16.0/20' does NOT exist within the specified list
13.14.32.0/19            : String is a valid IPv4 network. The string '13.14.32.0/19' does NOT exist within the specified list
13.14.64.0/18            : String is a valid IPv4 network. The string '13.14.64.0/18' does NOT exist within the specified list
13.14.128.0/17           : String is a valid IPv4 network. The string '13.14.128.0/17' does NOT exist within the specified list
13.15.0.0/16             : String is a valid IPv4 network. The string '13.15.0.0/16' does NOT exist within the specified list
13.16.0.0/12             : String is a valid IPv4 network. The string '13.16.0.0/12' does NOT exist within the specified list
13.32.0.0/11             : String is a valid IPv4 network. The string '13.32.0.0/11' does NOT exist within the specified list
13.64.0.0/10             : String is a valid IPv4 network. The string '13.64.0.0/10' does NOT exist within the specified list
13.128.0.0/9             : String is a valid IPv4 network. The string '13.128.0.0/9' does NOT exist within the specified list
14.0.0.0/8               : String is a valid IPv4 network. The string '14.0.0.0/8' does NOT exist within the specified list
15.0.0.0/12              : String is a valid IPv4 network. The string '15.0.0.0/12' does NOT exist within the specified list
15.16.0.0/20             : String is a valid IPv4 network. The string '15.16.0.0/20' does NOT exist within the specified list
15.16.16.0/24            : String is a valid IPv4 network. The string '15.16.16.0/24' does NOT exist within the specified list
15.16.17.0/28            : String is a valid IPv4 network. The string '15.16.17.0/28' does NOT exist within the specified list
15.16.17.16/31           : String is a valid IPv4 network. The string '15.16.17.16/31' does NOT exist within the specified list
15.16.17.18/32           : String is a valid IPv4 network. The string '15.16.17.18/32' does NOT exist within the specified list

Number of updates to WAF: 23

Update WAF IP set list via the following command:
aws waf-regional update-ip-set --region us-west-2 --ip-set-id 0a52dc3d-a2a9-4f18-8c04-27625833d74c --change-token 28a27a7f-0402-4cf7-b90d-a2ffda3cfd1e --updates Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="10.11.12.13/32"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="11.12.13.14/32"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="12.13.14.15/32"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.15.16/28"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.15.32/27"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.15.64/26"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.15.128/25"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.16.0/20"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.32.0/19"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.64.0/18"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.14.128.0/17"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.15.0.0/16"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.16.0.0/12"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.32.0.0/11"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.64.0.0/10"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="13.128.0.0/9"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="14.0.0.0/8"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="15.0.0.0/12"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="15.16.0.0/20"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="15.16.16.0/24"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="15.16.17.0/28"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="15.16.17.16/31"}' Action="INSERT",IPSetDescriptor='{Type="IPV4",Value="15.16.17.18/32"}'
```
