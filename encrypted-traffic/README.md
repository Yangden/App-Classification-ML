# Encrypted Traffic Classification End-To-End Pipeline

The code available in this project can be used to simulate encrypted traffic classification from capturing network packets, preprocessing the captured packets, and using a machine learning model (Random Forest in this case) to classify the captured packets.

## Prerequisites

- This project was written and tested on macOS Sequoia 15.1. Other operating systems may require additional configuration.
- All dependencies are listed in the `requirements.txt` file.

## Installation

1. Clone the repository:
    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Capture network packets:
    ```sh
    python capture_packets.py
    ```
    This script will actively capture packets on the network interface card specified in the code.

2. Preprocess the captured packets:
    ```sh
    python preprocess_packets_scapy.py
    python preprocess_bidirectional_packets_scapy.py
    ```

3. Train and classify using the Random Forest model:
    ```sh
    python classify.py
    ```

## Notes

- This project was written and tested on macOS Sequoia 15.1. If you are using a different operating system, you may need to configure some settings accordingly.
- Ensure that you have the necessary permissions to capture network packets on your machine.

