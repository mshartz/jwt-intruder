# jwt-intruder

More will be added to this as soon as I have the time. 

*JWT Intruder* is a Burp Suite extension designed to imbed intruder payloads inside of JSON Web Tokens (JWTs) for which you have the secret key. It automatically handles resigning of tokens so that users can execute Intruder attacks against JWT assertions. It operates independently of the *JWT Editor* extension, though it was heavily inspired by it, and it is highly recommended for use in determining the secret key upon which this extension relies. 

## Overview
*JWT Intruder* adds the following functionality:

* It populates a `JWT` tab in Proxy, Repeater, and Intruder within messages containing JWTs
* It allows for the specific placement of Intruder Payload positions, as denoted by §s, within JWT assertions

## Loading JWT Intruder

The easiest way of obtaining *JWT Intruder* is via Burp Suite's [BAppStore](pending).
See Burp Suite's [documentation](https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions) for additional details.

## JWT Tab

The `JWT` tab performs a basic decryption of any JWTs present in the HTTP message editor, detailing the `Header` (read-only for now) and `Payload' (editable). 

<img width="281" height="362" alt="Image" src="https://github.com/user-attachments/assets/418b80ce-3e48-4ac8-b11b-83fdd6491929" />

The `JWT` tab theb allows user to select the desire insertion point(s) within Burp Suite message editors. 

<img width="279" height="365" alt="Image" src="https://github.com/user-attachments/assets/512d5b02-4f3c-4d69-aed0-1792d731600b" />

It also populates a signing configuration section where users can select the signing algorithim (currently supported: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, and PS512) and input the Secret (`HMAC`) or Private Key (`RSA`): UTF-8 secret, Base64url secret, PKCS#8 PEM, or JWK JSON. 

<img width="1010" height="429" alt="Image" src="https://github.com/user-attachments/assets/58098577-c226-4950-9233-5dfdfe02037f" />

After applying the configuration using the `Apply Configuration` button, users can send the request to Intruder. In the Intruder tab, select the entire JWT as the payload, and select the desired payload. Current implementation only supports basic `Sniper` attacks, but development on additional functionality is pending. 

__IMPORTANT NOTE__: DISABLE URL ENCODING OF SPECIAL CHARACTERS!!!! This took the developer an unfortunately long time to realize. Please save yourselves the frustration. 

<img width="1155" height="256" alt="Image" src="https://github.com/user-attachments/assets/fff5da4e-c164-4dee-ae0a-cc031c987ace" />

After running the Intruder attack, users should be able to decrypt the JWTs sent to verify the payload sent.

<img width="664" height="780" alt="Image" src="https://github.com/user-attachments/assets/122daaf4-21a8-4088-b73a-97ff17116b4a" />

## Building JWT Intruder from source
*JWT Intruder* can be built from source
* Ensure that Java JDK 11+ and curl are installed
     * Author's Note: I know listing curl as a requirement seems like a gimme, but I'd rather over explain than under explain
* From root of project, run the command `./chmod +x build.sh` and `./build.sh` for Linux/MacOS or `./build.bat ` for Windows
* This should place the JAR file `jwt-intruder-all.jar` within the `dist` directory
* This can be loaded into Burp Suite by navigating to the `Extensions` tab, `Installed` sub-tab, clicking `Add` and loading the JAR file
* This BApp is using the newer Montoya API so it's best to use the latest version of Burp Suite 
