# Network IDS/IPS Project

A web-based Intrusion Detection and Prevention System (IDS/IPS) that helps monitor and manage network security through Snort rule generation and management and MISP integration.

## Features

- Snort rule generation with a user-friendly web interface
- MISP (Malware Information Sharing Platform) integration:
  - Export events from MISP to Snort rules
  - Scheduled automatic event exports
  - Event-specific rule generation
  - Real-time export logging
- Support for various rule components:
  - Protocol selection
  - IP address and port configuration 
  - Rule actions and options
  - Data size filtering
  - Reference linking
  - Threshold configuration
  - Protocol-specific options

## Getting Started

### Installation

1. Clone the repository:
```bash
git clone 
```
2. Create a virtual environment (if needed):
```bash
python -m venv venv
```
3. Switch to sudo user (preferable for running the server):
```bash
sudo su
```
4. Activate the virtual environment:
```bash
source venv/bin/activate
```
5. Install dependencies:
```bash
pip install -r requirements.txt
```
6. Start development server:
```bash
cd NIpsIds
# Copy the path to daphne from the virtual environment after installing the requirements
export DAPHNE_PATH=/path/to/venv/bin/daphne
daphe -b 0.0.0.0 -p 8080 NIpsIds.asgi:application
```

## MISP Integration

### Configuration

*You can follow the installation guide [here](https://www.misp-project.org/download/) if MISP is not yet installed on your machine.*

1. Set up MISP credentials in your environment:
After successfully setting up MISP, you can go to **Administration** > **List Auth Keys** to get the API key. Then set the following environment variables:
```bash
export MISP_URL="https://misp.local"
export MISP_KEY="your_api_key"
```
Or or you can set the variables in the .env file under `NIpsIds/dashboards` directory like the following:
```bat
MISP_URL="https://misp.local"
MISP_KEY="your_api_key"
```

## License

This project uses various components with MIT licenses. See individual license files in the static/admin directories for detailed licensing information.

## Contributing

Contributions are welcome. Please follow standard GitHub pull request procedures.
