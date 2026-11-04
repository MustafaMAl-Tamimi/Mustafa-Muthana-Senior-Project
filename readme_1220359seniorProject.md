Mustafa Muthana Ali Husein:: 1220359  
CS Senior Project

Part 1 \- Phishing Analysis Script//

How to Run:

1\. Place the script and email in the same folder  
2\. Get an API key from VirusTotal  
3\. From within the terminal, copy and paste this:

**Linux:** export virusTotalKey="YOUR\_VIRUSTOTAL\_API\_KEY"  
**Windows** **CMD:** \$env:virusTotalKey="YOUR\_VIRUSTOTAL\_API\_KEY"  
**Windows** **PowerShell:** set virusTotalKey=YOUR\_VIRUSTOTAL\_API\_KEY

4\. Run the script from the command line within the folder and enter the email file name.

**Linux:**python3 Senior-Project-Fin.py  
**Windows:** python Senior-Project-Fin.py

5\. Explore key artifacts of the file and determine its threat level.

This is my senior project as a CS student. I am doing this to build my skills in SOC (Security Operations Centre). To support this project, I completed the THM TryHackMe SOC Level 1 course, and to help with the coding, I studied “Automate the Boring Stuff with Python.” This is what I have so far, and it is a program to automatically extract all indicators of compromise when it comes to emails and phishing to make it easier for the SOC analyst to do their job and save more time for more complex tasks. This is all I have so far, and I am hoping I will have more time to create part 2 and part 3 related to log reading and detection…