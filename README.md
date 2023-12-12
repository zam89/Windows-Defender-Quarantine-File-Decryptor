Windows Defender Quarantine File Decryptor
===
This tool is use to decrypt file that been quarantined by Windows Defender. It also contains some Python code; as part of my blog - https://blog.khairulazam.net/2023/12/12/extracting-quarantine-files-from-windows-defender/

How to Compile
===
* Note: I'm developing this using IntelliJ IDEA. You can probably try to compile the code without the IDEA. Not sure if its work.

1. Clone this repo
2. Go to either DefenderEntriesDecryptor/src/ or DefenderFileDecryptor/src/
3. ```cargo build --release``` OR ```cargo build --target x86_64-pc-windows-gnu``` (i think so)

How to Run
===
1. For defender_file_decryptor.exe - to decrypt quarantine file
   ```
   defender_file_decryptor.exe <input_file> <output_file>
   ```
2. For defender_entries_decryptor.exe - to decrypt quarantine file entries
   ```
   defender_entries_decryptor.exe <input_file> <output_file>
   ```

Screenshot
===
TBD

Changelogs
===
- v0.1   (09 Dec 2023): First version of the code.

License
===
MIT License. Copyright (c) 2023 Mohd Khairulazam. See [License](https://github.com/zam89/Windows-Defender-Quarantine-File-Decryptor/blob/main/LICENSE).
