# Windows time sync (NTP) quick setup

Use this when a site network provides a local NTP source (router, switch, server) and the commissioning laptop needs stable time.

## Prerequisites
- Run the commands as Administrator.
- Replace `NTP_SERVER` with the IP address or hostname of the local NTP source.

## Enable the Windows Time service
Run in an elevated Command Prompt:
```
sc config w32time start= auto
net start w32time
```

## Point the client at the local NTP server
```
w32tm /config /manualpeerlist:"NTP_SERVER" /syncfromflags:manual /update
```

If this machine is acting as a local time source for others, add the reliable flag:
```
w32tm /config /manualpeerlist:"NTP_SERVER" /syncfromflags:manual /reliable:YES /update
```

## Verify the current time source
```
w32tm /query /source
w32tm /query /status
```

## Set the polling interval (15 minutes)
```
reg add HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient /v SpecialPollInterval /t REG_DWORD /d 900 /f
```

Restart the service:
```
net stop w32time
net start w32time
```

## Resync now
Run `ntp-update.bat` or run:
```
w32tm /resync /force
```

## References
- https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings?tabs=config
- https://community.spiceworks.com/t/configure-windows-server-to-query-an-external-ntp-server/1006321
