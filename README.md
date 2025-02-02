# Structur Network Driver for Windows 10 

## 🔧 Visual Studio 2022 Settings

To properly build the driver, configure the following settings in Visual Studio 2022:

### Project Properties
#### **Inf2Cat**
- **Use Local Time:** `Yes (/uselocaltime)`
  - *Path:* `Project Property > Inf2Cat > Use Local Time`

#### **Composer**
- **Input > Additional properties:**
  Add the following libraries:
  ```plaintext
  $(DDK_LIB_PATH)\fwpkclnt.lib
  $(DDK_LIB_PATH)\ndis.lib
  $(SDK_LIB_PATH)\uuid.lib

## 📌 Requirements
Windows Driver Kit (WDK) – Download: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

## 🛠 Contact
If you have any questions or suggestions, please contact the project author.

<div id="badges">
  <a href="https://t.me/jenya64">
    <img src="https://img.icons8.com/?size=512&id=63306&format=png"width="40" height="40" title="Telegram"/>
  </a> 
</div>
