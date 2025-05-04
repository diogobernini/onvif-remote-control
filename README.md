# ONVIF PTZ Camera Control

A simple Python terminal application to discover and control ONVIF PTZ (Pan-Tilt-Zoom) cameras on your network.

<img width="733" alt="Screenshot 2025-05-04 at 18 32 43" src="https://github.com/user-attachments/assets/001eb43d-8699-4251-b7d9-488e1fb9c63b" />

## Features

- Automatic discovery of ONVIF cameras on your network
- Saving and loading camera information between sessions
- Secure credential management
- PTZ control using keyboard arrow keys
- Zoom control with + and - keys

<img width="579" alt="Screenshot 2025-05-04 at 18 33 18" src="https://github.com/user-attachments/assets/0ea45005-54a7-4a6d-aada-5f6dfec0acaf" />


## Requirements

- Python 3.6+
- `readchar` library for keyboard input
- `netifaces` library for network interface discovery

## Installation

1. Clone the repository:
```bash
git clone https://github.com/diogobernini/onvif-remote-control.git
cd onvif-remote-control
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script:
```bash
python onvif_ptz_control.py
```

The application will:
1. Discover ONVIF cameras on your network
2. Allow you to select a camera
3. Prompt for authentication credentials
4. Provide PTZ control interface using keyboard keys

### Camera Controls

- ↑ ↓ ← → : Pan and tilt control
- + - : Zoom in/out
- q : Quit application

## How It Works

This application uses the ONVIF protocol, which is an open industry standard for IP-based security products like network cameras. It communicates with cameras using SOAP requests over HTTP/HTTPS.

The application:
1. Broadcasts WS-Discovery messages to find ONVIF-compatible devices
2. Authenticates with the selected camera using ONVIF authentication
3. Retrieves camera profiles and capabilities
4. Sends PTZ control commands when keyboard keys are pressed

## License

MIT
