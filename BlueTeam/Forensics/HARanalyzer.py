import json
from colorama import Fore, Style

def load_har(file_path):
    with open(file_path, 'r', encoding='utf-8') as har_file:
        return json.load(har_file)

def display_packet_table(entries):
    # Displaying header
    print("{:<5} {:<50} {:<15} {:<20} {:<10}".format("Index", "Requested Path", "Status Code", "File Type", "Size"))

    for i, entry in enumerate(entries):
        # Extracting relevant information
        request = entry.get('request', {})
        response = entry.get('response', {})

        requested_path = request.get('url', '')
        status_code = response.get('status', '')
        file_type = response.get('content', {}).get('mimeType', '')
        size = response.get('content', {}).get('size', '')

        # Color-coding based on response code
        if 200 <= status_code < 300:
            status_color = Fore.GREEN
        elif 300 <= status_code < 400:
            status_color = Fore.BLUE
        elif 400 <= status_code < 600:
            status_color = Fore.RED
        else:
            status_color = ''

        # Displaying information with color coding
        print(f"{status_color}{i:<5} {requested_path:<50} {status_code:<15} {file_type:<20} {size:<10}{Style.RESET_ALL}")

def display_packet_info(packet):
    request = packet.get('request', {})
    response = packet.get('response', {})

    print("\nSelected Packet Details:")
    print(f"Requested Path: {request.get('url', '')}")
    print(f"Status Code: {response.get('status', '')}")
    print(f"File Type: {response.get('content', {}).get('mimeType', '')}")
    print(f"Size: {response.get('content', {}).get('size', '')}")

def user_input_loop(entries):
    while True:
        display_packet_table(entries)
        print("\nSelect an option:")
        print("1. Inspect a packet")
        print("2. Filter the table by text")
        print("3. Exit")
        user_choice = input("Enter your choice (1-3): ")

        if user_choice == '1':
            try:
                packet_index = int(input("Enter the packet number to inspect: "))
                selected_packet = entries[packet_index]
                display_packet_info(selected_packet)

                while True:
                    print("\nSelect an option:")
                    print("1. Inspect the whole request")
                    print("2. Inspect request headers only")
                    print("3. Inspect request body only")
                    print("4. Inspect the whole response")
                    print("5. Inspect response headers only")
                    print("6. Inspect response body only")
                    print("7. Go back to the main packet table")

                    inspection_option = input("Select an inspection option (1-7): ")
                    if inspection_option == '1':
                        print(json.dumps(selected_packet, indent=2))
                    elif inspection_option == '2':
                        print(json.dumps(selected_packet.get('request', {}).get('headers', {}), indent=2))
                    elif inspection_option == '3':
                        print(selected_packet.get('request', {}).get('postData', ''))
                    elif inspection_option == '4':
                        print(json.dumps(selected_packet.get('response', {}), indent=2))
                    elif inspection_option == '5':
                        print(json.dumps(selected_packet.get('response', {}).get('headers', {}), indent=2))
                    elif inspection_option == '6':
                        print(selected_packet.get('response', {}).get('content', {}).get('text', ''))
                    elif inspection_option == '7':
                        break
                    else:
                        print("Invalid option. Try again.")
            except (ValueError, IndexError):
                print("Invalid packet number. Try again.")
        elif user_choice == '2':
            filter_text = input("Enter text to filter the table: ")
            filtered_packets = filter(lambda x: filter_text.lower() in json.dumps(x).lower(), entries)
            display_packet_table(list(filtered_packets))
        elif user_choice == '3':
            break
        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    # Replace 'your_file.har' with the path to your HAR file
    har_file_path = 'sampleHAR.har'

    har_data = load_har(har_file_path)
    entries = har_data.get('log', {}).get('entries', [])


    user_input_loop(entries)

