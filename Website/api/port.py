import socket
import asyncio

# A list of commonly used ports.
PORTS = [
    20, 21, 22, 23, 25, 53, 80, 67, 68, 69,
    110, 119, 123, 143, 156, 161, 162, 179, 194,
    389, 443, 587, 993, 995,
    3000, 3306, 3389, 5060, 5900, 8000, 8080, 8888
]

async def check_port(port, domain):
    """Check if a specific port is open on the given domain."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.5)  # 1500 ms timeout
        try:
            sock.connect((domain, port))
            return port  # Port is open
        except (socket.timeout, ConnectionRefusedError):
            return None  # Port is closed
        except Exception as e:
            return None  # Error while checking port

async def ports_handler(url):
    """Check open and closed ports for a given URL."""
    domain = url.replace("http://", "").replace("https://", "").split('/')[0]

    open_ports = []
    failed_ports = []

    async def check_all_ports():
        # Create tasks for all ports
        tasks = [check_port(port, domain) for port in PORTS]
        results = await asyncio.gather(*tasks)

        # Sort results into open and failed ports
        for port, result in zip(PORTS, results):
            if result is not None:
                open_ports.append(result)
            else:
                failed_ports.append(port)  # Append the port that failed

    try:
        await asyncio.wait_for(check_all_ports(), timeout=60)  # Increased timeout
    except asyncio.TimeoutError:
        return error_response("The function timed out before completing.")

    # Sort open_ports and failed_ports before returning
    open_ports.sort()
    failed_ports.sort()

    return {'open_ports': open_ports, 'failed_ports': failed_ports}

def error_response(message, status_code=444):
    """Return an error response."""
    return {'error': message}

# Example usage:
if __name__ == '__main__':
    url = "https://www.vupune.ac.in"  # Replace with your desired URL
    result = asyncio.run(ports_handler(url))
    print(result)
