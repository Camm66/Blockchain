# Blockchain Simulation
This program simulates the operation of a blockchain between multiple remote or local machines. As input, it takes raw string data consisting of medical patients and outputs the resulting blockchain in xml format.

Patient data is in the format:
 - 'Abraham Lincoln 1809.02.12 444-45-6888 GreviousWound Surgery Whiskey'

## Command-line compilation instructions
 Individually:
```
> javac Blockchain.java
```

Batch from root directory:

```
> javac *.java
```

## Instructions to run this program:
 In separate shell windows:
 ```
 > java Blockchain 0
 > java Blockchain 1
 > java Blockchain 2
 ```

 All acceptable commands are displayed on the console. This program is designed to run on a single machine. The host machines would need to be specified to run as a truly distributed application.

 ## Files needed to run this program
 e.g.:
1. Blockchain.java
2. BlockInput0.txt
3. BlockInput1.txt
4. BlockInput2.txt

Additional input files can be used in format: BlockInput[i].txt

## License
License information is available in the LICENSE.txt file.
