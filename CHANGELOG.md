# Changelog for the 2nd edition

## Documentation: 4
- The readme was well done.
> [ZG] Thanks.
README.md and CHANGELOG.md are either updated or added to reflect all improvement made below.
- The 'termcolor' dependency was missing, which did not allow us to cleanly setup and run the program.
> [ZG] Improved by adding requirements.txt to install all external library dependencies in one shot
## Setup: 2
- The setup was manual (no Make file), the setup was missing requirements, and there was no included requirements.txt (standard in python for shipping code)
> [ZG] Improved by adding requirements.txt and instructions in README.md.
## Core Requirements: 3
- Basic functions are there
> [ZG] Just a note, additional functionalities were added and listed in README.md "Key features" section #2-#8.
Couple of newly added features into this revision are:
    -#8 for statistic Plug-in design
    -Printing 'Current average' and 'Next Alert check' counting down onto the top of dashboard
- The app assumes a hard coded interface
> [ZG] Improved by taking user-supplied argument to overwrite default interface 'eth0' from command line argument
- When modified to run correctly, the app crashes after a while with a too many open files error
> [ZG] Bug fixed, passed stability test over night.
Also added alternative version using Scapy sniffer instead, both tested.
Even tested multiple instances of the program running in parallel, verified all instances had sniffed the complete traffic and produce expected information.
## Functional Design: 2
- The dependence on Wireshark is not good. Python is capable of network sniffing without requiring a 3rd party application.
> [ZG] Improved by fixing crashing, as well as provided alternative version using Scapy
- Hard coded interface identifier is not portable
> [ZG] Improved by adding support to overwrite default interface thru commandline argument
Also added "--help" argument to display help message
## Code Quality: 3
- The code pattern of functions defined in functions is not ideal and viewed as an anti-pattern at Datadog
> [ZG] Improved by rewriting the program using OOP/OOD principle aggressively.
Enhanced by employing Visitor, State and Chain-of-responsibility to demonstrate use of design pattern.
Also spitted classes into multiple .py
- try/except with out specific exception errors prior to a catch all is not ideal
> [ZG] Improved by replacing try/except all exceptions with specific exceptions
