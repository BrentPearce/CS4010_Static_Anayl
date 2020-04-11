# CS4010_Static_Anayl
## A project in python to perform static analysis of PE files

### Basic Description
This project preforms basic static analysis on a PE executable file including:
extracting strings, extracting imports, sending the file(or it's hash) to 
www.virustotal.com for simple analysis, and extracting the compilation time.

### Requirements
This program was created and tested using Python version 3.8 Additionally in 
order to use the program the following packages must be installed in the users 
environment or virtual environment:

* pefile
* hashlib
* requests
* googlesearch
* libpath
* lxml

### Description of Use
After the program is called the user is asked for the path to the file. As 
shown below. If the user enters an incorrect file path the prompt is repeated
until an existing PE file path is entered.

After the file path is provided the program displays a numbered menu, and by 
entering a numbers the corresponding report is printed to the screen. For 
example, if the user enters the number 5 and presses enter, then the dump 
strings option will be executed(all the strings used in the program will be 
printed to the terminal).

https://github.com/BrentPearce/CS4010_Static_Anayl/blob/master/resources/images/firstmenu.png?raw=true

You can also request definitions of dlls (3) or (4), 3 has issues due to 
google request limits but 4 lets you define only the dll functions you want to. 

![GitHub Logo](/images/logo.png)
Format: ![Alt Text](https://github.com/BrentPearce/CS4010_Static_Anayl/blob/master/resources/images/define.png?raw=true)

using 9 you can create a .txt file with most of the information from the other requests in it.
below is an example:

https://github.com/BrentPearce/CS4010_Static_Anayl/blob/master/resources/textexample

the file will be created in the same folder as the program. 
