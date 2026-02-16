# KamoDefender

## Next Generation Cyber Protection

KamoDefender is a professional web-based platform designed to enhance personal cybersecurity. It provides tools to analyze password strength, detect phishing URLs, and scan files for suspicious metadata, all within a modern and secure interface.

## Features

### 1. Password Security Analyzer
- **Strength Analysis**: Evaluates password complexity based on entropy and length.
- **Breach Check**: Securely checks if your password has been exposed in known data breaches using the **Have I Been Pwned API**.
- **Privacy First**: Uses k-Anonymity model. Only the first 5 characters of the SHA-1 hash are sent to the server. Your actual password never leaves your browser.
- **Password Generator**: Creates strong, random passwords for better security.

### 2. URL Phishing Detector
- **Link Scanning**: Analyzes URLs for potential threats.
- **Geolocation**: Identifies the hosting country and organization of the domain using **IP Geolocation**.
- **VirusTotal Integration**: (Optional) Can be configured to cross-reference URLs with the VirusTotal database for malware detection.

### 3. File Security Scanner
- **Local Analysis**: Checks file metadata (name, size, type) directly in the browser.
- **Safety Checks**: Identifies potentially dangerous file extensions and suspicious characteristics without uploading files to a remote server.

## Technologies Used

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **APIs**:
  - **Have I Been Pwned** (Password breach detection)
  - **ipapi.co** (IP Geolocation)
  - **VirusTotal** (Malware scanning - requires API key)

## Installation and Usage

1. **Clone or Download** the repository.
2. **Open the Project**:
   - Simply open `index.html` in your web browser.
   - For the best experience and to avoid CORS issues with some APIs, it is recommended to run the project using a local web server (e.g., Live Server in VS Code).

## Configuration (Optional)

To enable VirusTotal scanning capabilities:
1. Get a free API Key from [VirusTotal](https://www.virustotal.com/).
2. Open `api.js`.
3. Locate the `API_CONFIG` object.
4. Set `enabled` to `true` inside the `virustotal` section and paste your API key.

```javascript
virustotal: {
    baseUrl: 'https://www.virustotal.com/api/v3/',
    enabled: true,
    apiKey: 'YOUR_API_KEY_HERE'
}
```

## Privacy & Security

- **Client-Side Processing**: Most analysis happens directly in your browser.
- **Secure Hashing**: Passwords are hashed using SHA-1 before any network request, ensuring the plain text password is never exposed.
- **No Data Collection**: The application does not store or collect user data.

## Author

**Umidov Kamoliddin**
- Telegram: @um1dov7
- Email: umidovkamoliddin2006@gmail.com

---
© 2026 KamoDefender. All rights reserved.
