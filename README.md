# WineScore 🍷

A lightweight, low-level Win32/C utility that analyzes and "grades" your Windows environment to detect the presence of the Wine emulation layer. 

By running 14 distinct low-level checks, including direct PEB traversal, manual export table walking, and timing heuristics, this software generates a definitive "compatibility score" to determine if your application is running on native Windows or Wine.

## How To Compile:

You can easily compile WineScore either natively on Windows or cross-compile it from Linux/macOS. 
We've included automated scripts to handle compilation for you:

* **On Windows (using GCC/MinGW):**
  Simply run the batch file in your terminal:
  ```cmd
  compile.bat
  ```

* **On Linux / macOS (Cross-compiling for Windows):**
  Make the script executable and run it:
  ```bash
  chmod +x compile.sh
  ./compile.sh
  ```
