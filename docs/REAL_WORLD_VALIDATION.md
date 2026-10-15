# Real-device validation checklist

This document distinguishes automated loopback testing from a test on the actual sender, receiver, and Wi-Fi network. A localhost test cannot validate Wi-Fi routing, router client isolation, Windows Firewall, phone sleep behavior, or storage capacity.

## A. Prepare the exact same protocol version

1. Extract the same release ZIP on both sender and receiver, and use that release's `wireless_transfer.py` on both devices. This version uses a readiness handshake for file transfers; do not mix it with the earlier script.
2. On the receiving Windows laptop, open PowerShell in the extracted project folder and run:

   ```powershell
   py -m py_compile .\wireless_transfer.py
   py -m unittest discover -s tests -v
   ```

3. Confirm the destination volume has the size of the file plus at least 64 MiB free. The receiver checks this before accepting the file body.
4. In a separate PowerShell window, run `ipconfig` and find the IPv4 address under the *active Wi-Fi adapter on the receiving laptop*. Do not reuse an IP copied from another computer or an old network connection.

## B. Start the receiver

From the receiver's project folder, run:

```powershell
py .\wireless_transfer.py receive --host 0.0.0.0 --port 5001 --output-dir "$env:USERPROFILE\Downloads\received" --max-file-size-mib 8192 --idle-timeout 600
```

Keep this window open and prevent the laptop from sleeping. Allow Python through Windows Defender Firewall on the private network if Windows prompts. Do not expose port 5001 to the public internet.

## C. Validate the actual LAN path

- Connect Android and laptop to the same trusted Wi-Fi network where possible. Some campus, hotel, and guest networks intentionally block device-to-device traffic even when both devices have internet access.
- If a different Windows sender is available, check `Test-NetConnection <RECEIVER_WIFI_IPV4> -Port 5001`. On Android, send a short message using Termux (the test deliberately opens a real protocol connection):

  ```bash
  python ~/wireless_transfer.py send --host RECEIVER_WIFI_IPV4 --port 5001 --message "Android LAN validation"
  ```

  Replace `RECEIVER_WIFI_IPV4` with the actual address from the receiving laptop. Then send a small real file. A successful message alone does not validate file streaming.
- If the sender cannot connect, stop before attempting a large file. Confirm the receiver is listening, the IP belongs to the receiver, both devices can route to that IP, and Windows Firewall permits TCP 5001 on the current network profile. A `10.x.x.x` address does not by itself prove two devices can communicate; subnet routing and Wi-Fi isolation policies matter.

## D. Step up file sizes, verifying every result

1. Send a file of about 10–50 MiB.
2. Send a file larger than 100 MiB (for example, 512 MiB), then 1 GiB if storage and time allow.
3. Only then try the 6 GB archive. If you use the receiver example's `--idle-timeout 600`, also pass `--idle-timeout 600` on the sender command; each endpoint enforces its own inactivity timeout.

Example Termux command for a file in the phone's Downloads folder:

```bash
python ~/wireless_transfer.py send --host RECEIVER_WIFI_IPV4 --port 5001 --file "$HOME/storage/downloads/YOUR_FILE.rar" --max-file-size-mib 8192 --idle-timeout 600
```

Replace the IP and filename with the actual receiver address and file name.

The sender must print a final JSON response with `status: "ok"`, `size`, and `sha256`. Compare its SHA-256 with the received file using Windows PowerShell:

```powershell
Get-FileHash "$env:USERPROFILE\Downloads\received\YOUR_FILE_NAME" -Algorithm SHA256
```

On Android/Termux, the sender's final response includes the source hash it verified against the receiver acknowledgement. The receiver also logs its saved filename, byte count, and hash. The transferred file must exist, match the expected byte count, and have a matching hash. Merely reaching 100% sent is not a pass; the final integrity acknowledgement is required.

## E. Diagnose failures instead of repeatedly retrying

- **Immediate error before progress:** check the exact receiver error. File-size limit, insufficient space, wrong protocol version, or invalid path are likely.
- **`WinError 10054` or reset during transfer:** inspect the receiver window first. Disk becoming full, the receiver process closing, a sleep/network interruption, or an inactivity timeout can reset the connection.
- **Only large files fail:** compare source byte count with available destination space; use the same project version on both ends; test at 512 MiB and 1 GiB; keep the laptop awake and increase `--idle-timeout` if the connection can be idle for long periods.
- **Transfer finishes but hash differs:** do not use the received file. Save the error log and rerun on a stable trusted LAN.

## What counts as a validation pass?

Record OS/device, Wi-Fi path, file size in bytes, elapsed time, throughput shown by the sender, final receiver filename, sender/receiver SHA-256, and any errors. A pass requires complete file size, matching hashes, and no `.part` temporary files left behind. Repeat the 6 GB trial at least once before claiming repeatability. These results apply only to the tested device/network/storage combination.

## Security note

This educational prototype uses unencrypted TCP and does not authenticate the sender. Run it only on a trusted local network, and stop the receiver after the test. A public release or security-sensitive use requires a different threat model and authenticated encryption.
