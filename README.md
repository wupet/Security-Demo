# ---------------- Camera security ----------------
The camera system we have relies completely on the security of the Local Network. Most major vulnerabilities are stopped by a more secure and modern router. However, the camera system itself is not particularly secure. If we assume that the Network is not secure enough say allowing for ARP spoofing, the system leaves many vulnerabilities open that we will demo here. 

# ---------------- Demo \#1 ----------------
In this demo, we will demonstrate how an attacker could possibly watch a camera stream without the required credentials.

### Requirements
tshark, and therefore wireshark, scapy, vlc player or any other way to connect to an rtsp connection, ffmpeg, and windows powershell (you may need to adjust some of the commands if you are using a different terminal).

### Background
The hikvision camera system at hand uses the real time stream protocol (rtsp) to connect and transport stream data to a machine on the local network. However, the camera system uses neither rtsps (encrypts signaling) nor srtp (encrypts media) so it can be relatively easy to reconstruct the media when sniffing the wifi for packets. Additionally, even if rtsps was used, it only encrypts the signaling even though it is still relatively reasonable to guess the encrypted data needed to reconstruct the media. Either way, this demo demonstrates that the rtsp stream is not secure. First, how does this rtsp streams work? This system first uses a tcp handshake to ensure a reliable connection between the server and the client. Next, they use rtsp handshake to agree on the exact parameters of the video. Afterwards, they send the media through rtp packets. All of which besides the password is passed completely unencrypted. Thus, as a observing bystander, we can reconstruct the stream data without the need for a password. 
In other words, if someone else is watching the stream, we can watch it with them but with this method, we would not be able to start a stream by ourselves. One caveat is that we need the video's metadata (such as the compression algorithm used, the play back speed, etc) to properly reconstruct the captured media packets. This is relevant if we for some reason aren't able to capture the metadata, such as if we start sniffing halfway into a stream or if the signaling is encrypted. However, even without the captured metadata of the current session, if you have the SDP data of a previous session (as I doubt it changes often) you should be able to reuse it. Additionally as mentioned earlier, it is entirely possible to guess since there aren't to many options and some are more popular than others.
Something to note is that many modern routers will not send important information in a way that is easy to sniff. However, some older routers do.

### Overview
In demo \#1, we will start sniffing the wifi traffic with tshark and save the raw captured packets to a file. Then we will reconstruct the media using the provided python script and then convert it into a watchable video with ffmpeg. Although not technically required, this demo is designed such that it relies on be able to capture the beginning metadata. Additionally, this demo assumes you know the camera system's IP address which is reasonable to find if you just scan for rtsp packets using wireshark. 
Commands will be italicized and adjustable data will be underlined.


### Step 1
In powershell, execute the command _tshark -D_. This will reveal the network iterfaces of your device. You will need to find the one you need to sniff. In the author's case, this was interface 4 for Wi-Fi. note the number associated with it.

### Step 2
In powershell, cd into the same directory as extract_h265.py and execute the command *tshark -i <u>4<u> -f "<u>host clientIP and host serverIP<u>" -w captured.pcap*. 
* The -i option indicates which interface tshark should scan for. 
* The -f option indicates which filters you would like to use. The author recommends "host clientIP and host serverIP" where clientIP is the IP address of the other system watching the stream (which in this case will be the same IP as the one executing the tshark) and serverIP is the IP address of the camera system. 
* The -w option indicates where to write the output data.

### Step 3
Start the rtsp connection in vlc player by pressing Ctrl+n, pasting the rtsp url, and pressing play. At this point, you can do pretty much anything in front of the camera.

### Step 4
Close out of the rtsp connection in vlc player and then press Ctrl+c in powershell to stop tshark. At this point, a file named captured.pcap should have appeared in the same directory as the extract_h265.py file.

### Step 5
Execute the following command *py extract_h265.py captured.pcap unprocessed_video.h265* to convert the raw data to a compressed video file.
* captured.pcap is the input file
* unprocessed_video.h625 is the output file

### Step 6
Execute the following command *ffmpeg -fflags +genpts -analyzeduration 100M -probesize 100M -i unprocessed_video.h265 -c copy recovered.mkv* to decompress the video file allowing for proper viewing and watch the recovered.mkv video to verify that the demo worked. 


# ---------------- Demo \#2 ----------------
In this demo, we will demonstrate how an attacker could possibly execute a Denial of Service (DoS) attack. 

### Requirements
wireshark, vlc player, and curl. (commands may be different on different systems. the author wrote these for windows powershell)

### Background
This camera system uses their http port as an admin/management portal for their array of cameras. This is significant because http does not encrypt any of the transmitted data similar to the rtsp in demo \#1. Thus, we can observe many different things from sniffing the transmitted packets. This camera system also uses two main forms of authentication in the http port. The first is digest authentication. This form of authentication is relatively secure and uses a challenge response protocol to verify the request maker has the password. The second is cookie-based authentication. This form of authentication not secure at all since the cookies are transmitted in plain text allowing attackers to sniff, copy, and use the cookies of a legitimate user. We will be exploiting this second form of authentication. There are a couple things to note: 
1. The camera system cross references the cookies with the client's IP address. However, it is not impossible to spoof your IP to get around this. We will assume that you can send from their IP address.
2. The system gives the option switch from digest to digest/basic certification. However, basic certification is not secure.
3. The cookies are unique to each session and IP. Not all routers will allow you to read other people's data. We will assume that you can read any data in transit. 
4. The planned reset should also be vulnerable to the same attack.

### Overview
We will sniff the network until we detect someone has logged onto the camera system's http port. When this happens, we will capture the cookies they use and reuse them to reset the system forcing the camera's and the management/admin system to go down temporarily.

### Step 1
Open an rtsp stream in vlc player.

### Step 2
Open wireshark and sniff on the same interface that you will connect to the server. Filter only the packets that are to or from the server's IP address. ex: ip.addr == 11.11.11.11 

### Step 3
Log onto the admin system with http://<u>serverIP<u>:<u>http_port<u> on one of your browsers. Once you are in, click a few buttons.

### Step 4
Stop recording on wireshark. use Ctrl+f to find a packet with "cookie" in the packet details. It will be under the Hyper text transfer protocol tab. find it, right click on the cookie tab and click copy then click value.

### Step 5
Once you get the cookie, replace the cookie and the IP address in the following curl command and execute it.

*curl.exe ^"http://<u>serverIP<u>/ISAPI/System/reboot^" ^*
  *-X PUT ^*
  *-H ^"Cookie: <u>cookie<u>^"*


### Step 6
Observe the vlc player stream and your http connection. These should both stop responding within a few seconds. If they do, the demo was a success.