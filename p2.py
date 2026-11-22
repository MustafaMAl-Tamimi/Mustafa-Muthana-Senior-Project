import re
import os




maxFailedLogin = 5

def readLog(file):
    if not os.path.isfile(file):
        print("File does not exist!")
        return []

    logFile = open(file , "r", encoding="utf-8", errors = "replace")
    
    logFileLines = logFile.readlines()
    logFile.close()
    return logFileLines


def logAnalyzer(logFileLines):
    failedLogins = {}
    successfulLogins = []
    failedTotal = 0
    successfulTotal = 0

    failedExtract = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)")
    successfulExtract = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+)")
    for line in logFileLines:
        failedExtractMatch = failedExtract.search(line)
        if failedExtractMatch:
            username = failedExtractMatch.group(1)
            ipAddress = failedExtractMatch.group(2)
            failedTotal = failedTotal + 1
            
            if ipAddress in failedLogins:
                failedLogins[ipAddress] = failedLogins[ipAddress] + 1
            else:
                failedLogins[ipAddress] = 1
        successfulExtractMatch = successfulExtract.search(line)
        if successfulExtractMatch:
            username = successfulExtractMatch.group(1)
            ipAddress = successfulExtractMatch.group(2)
            login = {
            "username" : username, "ipAddress" : ipAddress
             }
            successfulLogins.append(login)
            successfulTotal = successfulTotal + 1
    return failedLogins, successfulLogins, failedTotal, successfulTotal

def bruteForceDetection(failedLogins):
    alerts = []
    
    print("=" * 32)
    print("LOG ANALYSIS REPORT")    
    print("=" * 32)
    print()
    for ipAddress in failedLogins:
        numberOfAttempts = failedLogins[ipAddress]
        if numberOfAttempts >= maxFailedLogin:
            alert = {"ip" : ipAddress, "attempts" : numberOfAttempts, "severity" : "High"}
            alerts.append(alert)
    return alerts

def displayAlerts(alerts, failedLogins, successfulLogins, failedTotal, successfulTotal):
    print
    print("Total Failed Logins: " +str(failedTotal))
    print("Total Successful Logins: " +str(successfulTotal))
    print("Total Unique IPs With Failed Logins: " + str(len(failedLogins)))
    print("Limit for Failed Logins: " + str(maxFailedLogin) + " attempts")
    print()    
    print("--- Brute-Force Alerts ---")
    if len(alerts) == 0:
        print("No Brute Force Attack")
    else:
        for alert in alerts:
            print("Severity: " + alert["severity"] + " | IP Address: " + alert["ip"] + " | Number of Attempts " +           str(alert["attempts"]))
    print()
    print("--- Failed Logins By IP ---")
    if len(failedLogins) == 0:
        print("No Failed Logins")
    else:
        for ipAddress in failedLogins:
            print(ipAddress + " : " + str(failedLogins[ipAddress]))

    print()
    print("--- Successful Logins ---")
    if len(successfulLogins) == 0:
        print("No Successful Logins")
    else:
        for login in successfulLogins:
            print(login["username"] + " from " + login["ipAddress"])
    
    print()
    print("--- Possible Comprimise ---")

    susCount = 0
    for login in successfulLogins:
        for alert in alerts:
            if login["ipAddress"] == alert["ip"]:
                print("Possible Comprimise!! " + login["username"] + " : " + login["ipAddress"])
                susCount = susCount + 1
        if susCount == 0:
            print("No Possible Comprimise..")
        print()




logFileLines = readLog("test_auth.log")

failedLogins, successfulLogins, failedTotal, successfulTotal = logAnalyzer(logFileLines)

alerts = bruteForceDetection(failedLogins)

displayAlerts(alerts, failedLogins, successfulLogins, failedTotal, successfulTotal)


