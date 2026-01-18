# DS2_DirectConnect

Just a little thing I hacked up. This project setups up and compiles a version.dll file, which refers to functional of the orginal version.dll but adds a bunch of hooks to manage components effectely converting the LAN section of the game client into a network lobby. the ds2_ip.txt file  holds the public ip of the lobby server. 

still in development at this point will update as im working on. 

-*.exe is the cracked client with the multiplayer tab enabled(i will be recompiling one myself but this isnt that)
-version.dll is the hacked dll that is hijacking the network fuctions in order to inject the provided -ip, 
-ds2_ip.txt is the file it is looking for

all three of these files are to be put into the main game folder where the current .exe is, id suggest creating an extra folder and moving the old *.exe into it before this so that you can revert to the orginal at anytime. 

