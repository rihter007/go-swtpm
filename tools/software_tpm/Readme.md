A local binary that allows to take request from TPM clients like tpm2 tools via different protocols.
Current support:
- socket upon TCP
- mssim

Example:
./software_tpm -- -mssim
./tpm2_getcap handles-persistent -T "mssim:host=localhost,port=2321"
