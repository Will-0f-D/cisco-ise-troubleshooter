"""SSH to a Cisco switch and run a single show command (Netmiko)."""
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


class SwitchConnectionError(Exception):
    pass


class SwitchAuthError(Exception):
    pass


def run_command(host: str, username: str, password: str, command: str, secret: str = "", port: int = 22, device_type: str = "cisco_ios") -> str:
    if not host:
        raise SwitchConnectionError("Host switch mancante")
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if secret:
        device["secret"] = secret
    try:
        with ConnectHandler(**device) as conn:
            if secret:
                conn.enable()
            return conn.send_command(command, read_timeout=20)
    except NetmikoAuthenticationException as e:
        raise SwitchAuthError(f"Credenziali rifiutate da {host}") from e
    except NetmikoTimeoutException as e:
        raise SwitchConnectionError(f"Timeout: {host} non raggiungibile su porta {port} (SSH abilitato?)") from e
