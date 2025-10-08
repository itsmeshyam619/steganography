# Image Steganography with Cryptography

A Streamlit web app that hides encrypted messages inside images (LSB steganography) and extracts + decrypts them. Built with Python, Pillow and cryptography.

## Features
- Hide text inside images using Least Significant Bit (LSB) steganography
- AES encryption of messages (password-based key derivation)
- Extract and decrypt hidden messages via a Streamlit UI
- Supports PNG / JPG / JPEG cover images
- Debug output for decoding and decryption issues

## Prerequisites
- Python 3.8+
- Git (optional)

## Install
1. Clone or copy the project to your machine.
2. Create and activate a virtual environment (recommended).
3. Install dependencies:
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
```
Note: `base64` is part of Python stdlib — it does not need to be installed.

## Run the app
From project root:
```bash
streamlit run app.py
```
Open the URL shown in the terminal (usually http://localhost:8501).

## Run in VS Code (debug)
Create a `launch.json` in `.vscode` with a Streamlit config, or use this snippet:
```json
{
  "name": "Streamlit: Run app.py",
  "type": "python",
  "request": "launch",
  "program": "-m",
  "args": ["streamlit", "run", "app.py"],
  "console": "integratedTerminal"
}
```
Set breakpoints and start debugging via the Run view.

## Usage
- Encrypt & Hide: enter message, choose password, select a cover image, then hide.
- Extract & Decrypt: upload stego image and enter the password used during encryption.

The app will show debug info when decryption fails (base64 length, decoded hex, etc.) to help troubleshooting.

## Project structure (important files)
- app.py — Streamlit UI
- encryption.py — encryption + encoding and steganography encode
- decryption.py — decoding from image + decryption
- requirements.txt — Python dependencies

## Common issues & debugging tips
- Base64 padding errors: add padding before decoding (`'=' * (4 - len(s) % 4)`).
- UnicodeDecodeError after decryption: try alternative decodings (latin-1) or show hex of plaintext.
- "Decoded data too short": ensure encrypted payload includes salt (16B) + IV (16B) + ciphertext.
- Use print / st.write for intermediate lengths and hex dumps:
  - length of base64-decoded bytes
  - hex of salt, IV, ciphertext
- Save uploaded files to a secure temp directory and delete after use.

## Security considerations (prototype)
- Sensitive data may remain in memory or temp files — use secure deletion and memory handling for production.
- No rate-limiting or password strength enforcement.
- LSB steganography is detectable with steganalysis tools.
- Error messages may leak implementation details — sanitize for production.

## Suggested future enhancements
- Stronger key handling: use secure key storage, HSM or KMS for production.
- Improve steganography: adaptive/transform-domain methods and error correction.
- Enforce password complexity and add attempt-limiting (rate limiting).
- Secure temp file handling and in-memory encryption of sensitive data.
- Add automated tests and CI, and containerize the app.

## Contributing
- Fixes and improvements welcome. Open an issue or PR with description and tests.



Current Risks & Vulnerabilities 🔒
1. Steganography Related
LSB Detection: Current LSB implementation might be detected by steganalysis tools
Limited Capacity: Only uses 1 bit per color channel, limiting message size
Format Restrictions: Only supports PNG output for steganography
2. Cryptography Related
Password Handling:
Passwords stored in plain text during session
No password strength requirements
No salt rotation mechanism
3. Application Security
File Handling:
Memory Management: Sensitive data remains in memory
Error Messages: Detailed error messages could reveal system information


Advanced Features

Multiple steganography algorithms
Support for different file formats
Real-time steganalysis detection
Security Improvements

Two-factor authentication
Secure key management
Anti-tampering mechanisms
Performance Optimization

Parallel processing for large images
Compression techniques
Caching mechanisms
User Experience

Progress indicators
Batch processing
Mobile responsiveness
Integration Capabilities

API endpoints
Cloud storage support
Offline mode
