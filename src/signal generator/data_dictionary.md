Below is a data dictionary for attack‐timing JSON. Each top-level key is the name of an attack, and its value is an object with three fields.

| Field Path                   | Data Type | Description                                                                                       |
|-------------------------------|-----------|---------------------------------------------------------------------------------------------------|
| **\<AttackName\>**            | Object    | Container for timing metrics of a specific attack. `<AttackName>` maybe e.g. `Bruteforce`,  `ARP_eveadropping`,`TCP_flag_injection` or `FDIA`. |
| ├─ **start**                  | String    | Timestamp when the attack started, in “YYYY-MM-DD HH:MM:SS.ffffff” format (no timezone).         |
| ├─ **end**                    | String    | Timestamp when the attack ended, in “YYYY-MM-DD HH:MM:SS.ffffff” format (no timezone).           |
| └─ **duration**               | String    | Difference between end and start, formatted as “H:MM:SS.ffffff” (hours:minutes:seconds.microsec). |

**Example**  
- `Bruteforce.start` = `"2025-04-22 22:11:18.805617"`  
- `Bruteforce.end` = `"2025-04-22 22:21:21.150666"`  
- `Bruteforce.duration` = `"0:10:02.345049"`