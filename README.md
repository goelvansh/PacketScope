# Packet Capture Analysis Tool

The Packet Capture Analysis Tool is a Python application that allows you to capture and analyze network packets based on filter protocols, visualize protocol distribution, and export packet information as CSV.

## Prerequisites

Before running the application, ensure that you have the following installed on your system:

- Python 3.x: [Download Python](https://www.python.org/downloads/)
- Git (optional): [Download Git](https://git-scm.com/downloads)

## Getting Started

Follow the steps below to set up and run the Packet Capture Analysis Tool on your machine.

### Clone the Repository

You can either download the ZIP archive of the repository or use Git to clone it. Open your terminal or command prompt and run:

```bash
git clone https://github.com/your-username/packet-capture-analysis.git
```
## Navigate to the Project Directory

Before running the application, make sure you have navigated to the project directory. Open your terminal or command prompt and change into the `packet-capture-analysis` directory:

```bash
cd packet-capture-analysis
```
## Now you are in the project directory, and you can proceed with the next steps.

## Create a Virtual Environment (Optional but Recommended)

It is recommended to use a virtual environment to isolate the dependencies for this project. If you don't have `virtualenv` installed, you can install it using `pip`:

```bash
pip install virtualenv
```
```bash
virtualenv venv
```
### Activate the virtual environment(Only for Windows):
```bash
venv\Scripts\activate
```
## Install Dependencies
###With the virtual environment activated, you can now install the required Python packages using the requirements.txt file:
```bash
pip install -r requirements.txt
```
## Run the Application
```bash
python pca.py
```
## Usage

To use the Packet Capture Analysis Tool, follow these steps:

1. Launch the application by running the `pca.py` script as mentioned earlier.

2. Enter the desired number of packets you want to capture and analyze in the "Number of Packets" field.

3. 
   - Enter the protocol number (e.g., 6 for TCP) in the "Filter Protocol" field to capture only packets of that protocol. Leave empty to capture all protocols.
   - Specify the source IP address in the "Source IP" field to capture packets originating from a specific IP address.
   - Specify the destination IP address in the "Destination IP" field to capture packets destined for a specific IP address.
   - Enter the source port number in the "Source Port" field to capture packets originating from a specific port.
   - Enter the destination port number in the "Destination Port" field to capture packets destined for a specific port.

4. Click the "Run" button to start capturing and analyzing packets based on your specified criteria.

5. The application will display the following information:
   - The number of packets captured and analyzed.
   - The total data transferred in bytes for the filtered packets.
   - The average size of the filtered packets in bytes.
   
6. Additionally, a histogram displaying the distribution of packet sizes will be shown.

7. The application will also list the captured and filtered packets in a listbox. You can select a packet from the listbox to view its details in a new window.

8. To visualize the distribution of protocols in the captured packets, click the "Visualize Protocol Distribution" button. A pie chart will be displayed showing the percentage distribution of each protocol.

9. To export the information of filtered packets to a CSV file, click the "Export as CSV" button. The data will be saved in a file named "captured_packets.csv" in the project directory.

10. If you want to replay the captured packets with a specified delay, click the "Replay Packets" button.

## License

This project is licensed under the [MIT License](LICENSE).
