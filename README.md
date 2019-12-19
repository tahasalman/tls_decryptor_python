<h1>Decrypting HTTPS Traffic for Monitoring</h1>

<h2> Introduction </h2>
This tool is meant to be integrated with a packet sniffer so that encrypted
HTTPS packets can be decrypted for analysis. Currently, it will only work with TLS 1.2
and the cipher suite TLS_RSA_WITH_AES_128_CBC_SHA. In the future I intend to add support
for more cipher suites and more extensions

<h2>Getting Started</h2>
> pip install -r requirements.txt

1) Save your private key in keys/privkey.pem
2) Go to tls/ directory 
3) Update data in test_data/data. Each file must contain a stream of hex bytes. Check the files for examples
4) > python3 run.py
5) Decrypted packets will be printed out and stored in the specified files

<h2> Future Tasks </h2>

1) Eventually integrating this with a python sniffer program to make it decrypt traffic on-the-fly

2) Adding support for more cipher suites

3) Refactoring code to allow for multi-processing

4) Looking into TLS 1.3
