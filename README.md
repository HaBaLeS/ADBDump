# ADBDump
Command line tool written in Go to monitor the connection between Android adb and and a Android device. As the connection
is TCP based even if you run over USB it is easy to capture the traffic.

Tool was created to analyze a specific problem on instrumented test execution. It dumps the commands that are not binary
to transfer any files. You will see the ADB internal protocoll and output like on _adb logcat_.
 
You can live capture on any device or replay a existing pcap capture.

***For live Capture you need root. As always before you run anything as root, have a look a the code.***

Install with 
  
    go get -v  -u  github.com/HaBaLeS/ADBDump

if $GOPATH/bin is in your PATH run it with 

    ADBDump -r filep.pcap
    
to replay a captured dump    

    sudo ADBDump

for a live dump or

    sudo ADBDump -h 
    
for Options



