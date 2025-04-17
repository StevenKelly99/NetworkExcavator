  _   _      _                      _      ______                          _             
 | \ | |    | |                    | |    |  ____|                        | |            
 |  \| | ___| |___      _____  _ __| | __ | |__  __  _____ __ ___   ____ _| |_ ___  _ __ 
 | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ / |  __| \ \/ / __/ _` \ \ / / _` | __/ _ \| '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <  | |____ >  < (_| (_| |\ V / (_| | || (_) | |   
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |______/_/\_\___\__,_| \_/ \__,_|\__\___/|_|   
                                                                                         
                                                                                         
Thank you for using NetworkExcavator! The perfect lightweight, cross platform tool for network artifact reconstruction and PCAP analysis
--------------------------------------------------------------------------------------
## Requirements:
Python 3.8+
pip (Package manager for Python)
Tshark (for HTTP export from PCAPs)
--------------------------------------------------------------------------------------
Instructions for requirements.txt:
1. Open a terminal/ command prompt and cd into the root directory of the program
2. Use this command:
	- For Windows:  pip install -r requirements.txt
	- For Mac: pip3 install - r requirements.txt
This installs all required Python libraries for the tool to function
--------------------------------------------------------------------------------------
#Installation Instructions - Windows#
1. Install Python (https://www.python.org/downloads/) *(Ensure to tick "Add to PATH" when Installing)*
2. Install Wireshark which includes Tshark (https://www.wireshark.org/download.html)
Validate Tshark using the command: tshark --version
3. Ensure Wireshark is added to System Variables (in order for Tshark to work):
	- From the search bar go to "Edit the System Environment Variables"
	- Use the "Environment Variables" button when met with it
	- On System variables tab add your Wireshark installation location (by default C:\Program Files\Wireshark) to PATH
4. Go to the tools download location (by default C:\users\your name\downloads) and run the tool from the "Windows_Release" folder
--------------------------------------------------------------------------------------
#Installation Instructions - macOS#
1. It is recommended to use Homebrew on macOS as it is the easiest way to manage packages on Apple devices (https://brew.sh/)
2. Use brew to install Python and Tshark:
	- brew install python
	- brew install wireshark
3. Go to the tools download location (by default in the home directory ~/Downloads) and run the tool from the "MacOS Release" folder
--------------------------------------------------------------------------------------
#Installation Instructions - Linux#
1. Update then Install Python, PIP and Tshark:
	- sudo apt update
	- sudo apt install python3 python3-pip tshark -y
2. Go to the directory the tool is located using the "cd" command
3. Open a terminal in the root directory and run:
	- python main.py
Or alternatively the main.py can be ran from a code editor like Visual Studio Code
--------------------------------------------------------------------------------------
Usage:
Simply run the tool, add your PCAP file when prompted.
--------------------------------------------------------------------------------------
*If Python was not added to System Variables it must be added manually by adding python3 to PATH inside Environment Variables like previously with Tshark*
If an issue arises with images not displaying it is most likely due to Tshark, please follow instructions above to ensure Tshark is working correctly

