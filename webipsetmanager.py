from flask import Flask, request
import subprocess
import time
import threading

app = Flask(__name__)

# IPset name and iptables chain
# The name of the ipset set.
IPSET_NAME = "allowed_browser_ips"
# The iptables chain to which the rule will be added.
# Common choices are 'INPUT' for incoming connections.
IPTABLES_CHAIN = "INPUT"

def init_ipset_and_iptables():
    """
    Initializes the ipset set and adds the iptables rule.
    This function should be called once when the Flask application starts.
    It checks if the ipset exists and creates it if not.
    It also checks if the iptables rule exists and adds it if not,
    to prevent duplicate rules on restarts.
    """
    print(f"Initializing IPset '{IPSET_NAME}' and IPTables rule for chain '{IPTABLES_CHAIN}'...")
    try:
        # Create ipset set if it doesn't exist
        # 'hash:ip' type stores IP addresses.
        # 'timeout 7200' sets a default timeout of 2 hours (7200 seconds) for entries.
        # 'exist' flag prevents an error if the set already exists.
        subprocess.run(
            f"sudo ipset create {IPSET_NAME} hash:ip timeout 7200 exist",
            shell=True,
            check=True,  # Raise CalledProcessError for non-zero exit codes
            text=True,
            capture_output=True
        )
        print(f"IPset '{IPSET_NAME}' created or already exists.")

        # Add iptables rule to allow traffic from the ipset
        # Check if the iptables rule already exists to avoid duplication
        check_rule_cmd = (
            f"sudo iptables -C {IPTABLES_CHAIN} -m set --match-set {IPSET_NAME} src -j ACCEPT"
        )
        try:
            subprocess.run(check_rule_cmd, shell=True, check=True, text=True, capture_output=True)
            print(f"IPTables rule for '{IPSET_NAME}' already exists in chain '{IPTABLES_CHAIN}'.")
        except subprocess.CalledProcessError as e:
            # If the check command fails, it means the rule doesn't exist, so add it
            add_rule_cmd = (
                f"sudo iptables -A {IPTABLES_CHAIN} -m set --match-set {IPSET_NAME} src -j ACCEPT"
            )
            subprocess.run(add_rule_cmd, shell=True, check=True, text=True, capture_output=True)
            print(f"IPTables rule added for '{IPSET_NAME}' to chain '{IPTABLES_CHAIN}'.")

    except subprocess.CalledProcessError as e:
        print(f"Error during IPset/IPTables initialization:")
        print(f"Command: {e.cmd}")
        print(f"Return Code: {e.returncode}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        # Exit if critical initialization fails
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during initialization: {e}")
        exit(1)

@app.route('/')
def home():
    """
    The main route for the web server.
    When a browser accesses this route, its IP address is added to the ipset.
    """
    user_ip = request.remote_addr
    if not user_ip:
        return "Error: Could not determine your IP address.", 400

    print(f"Received request from IP: {user_ip}")

    try:
        # Add the user's IP address to the ipset set.
        # 'timeout 7200' sets the expiry for this specific IP entry to 2 hours.
        # 'exist' flag updates the timeout if the entry already exists.
        cmd = f"sudo ipset add {IPSET_NAME} {user_ip} timeout 7200 exist"
        subprocess.run(
            cmd,
            shell=True,
            check=True,  # Raise CalledProcessError for non-zero exit codes
            text=True,
            capture_output=True
        )
        print(f"IP address {user_ip} added to ipset '{IPSET_NAME}' with 2-hour timeout.")
        return (
            f"您的IP地址 {user_ip} 已被添加到允许访问列表，有效期2小时。欢迎访问！"
            f"<br><br>您可以通过命令行运行 'sudo ipset list {IPSET_NAME}' 来查看当前允许的IP。"
        )
    except subprocess.CalledProcessError as e:
        print(f"Error adding IP to ipset:")
        print(f"Command: {e.cmd}")
        print(f"Return Code: {e.returncode}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return "Error: Failed to add your IP address to the allowed list. Please contact administrator.", 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "Error: An unexpected error occurred. Please try again later.", 500

if __name__ == '__main__':
    # It is crucial to ensure that the user running this script
    # has the necessary sudo privileges to execute ipset and iptables commands
    # without requiring a password. This is typically configured via the /etc/sudoers file.
    #
    # Example /etc/sudoers entry for a user 'your_user':
    # your_user ALL=(root) NOPASSWD: /usr/sbin/ipset, /usr/sbin/iptables
    #
    # Or, if running via a web server like Apache/Nginx with a 'www-data' user:
    # www-data ALL=(root) NOPASSWD: /usr/sbin/ipset, /usr/sbin/iptables
    #
    # This setup is critical for the script to function correctly without manual intervention.

    # Initialize ipset and iptables rules before running the Flask app
    init_ipset_and_iptables()

    # Run the Flask application.
    # 'host='0.0.0.0'' makes the server accessible from any IP address.
    # 'port=80' listens on the standard HTTP port.
    # In a production environment, you would typically use a WSGI server like Gunicorn or uWSGI
    # and reverse proxy with Nginx/Apache.
    app.run(host='0.0.0.0', port=80)
