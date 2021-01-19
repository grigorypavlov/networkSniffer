# networkSniffer

## Installation

networkSniffer depends on the jNetPcap library.

1. Download jnetpcap from: [sourceforge](https://sourceforge.net/projects/jnetpcap/)
2. Extract the .zip file
3. In the extracted foler are two important files:
   *jnetpcap.dll* and *jnetpcap.jar*
4. Copy and paste the .dll-file to *C:\Windows\System32*

Adding the library to a existing project in AndroidStudio

1. Switch the folder structure from Android to **Project**
2. Search for the libs folder inside app. Create it if it doesn't exists
3. Paste the .jar-file into the libs folder
4. Right-click the .jar and click on **Add as library**
5. Import to a class with

    import org.jnetpcap.*;

