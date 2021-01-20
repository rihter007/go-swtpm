A local binary that allows to take request from TPM clients like tpm2 tools via different protocols.

Current support:
- socket upon TCP
- mssim

Example:

$ ./software_tpm -- -mssim

$ export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"

$ tpm2_getcap handles-persistent
