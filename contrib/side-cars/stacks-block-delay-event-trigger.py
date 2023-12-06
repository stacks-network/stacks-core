"""
Monitors the time difference between Stacks blocks and Bitcoin blocks, triggering an event
when the time difference exceeds a specified threshold.

This script continuously checks the time difference between the latest Stacks
block and the latest Bitcoin block. If the time difference exceeds a user-defined
threshold, the script executes a user-defined shell command. The script utilizes
exponential backoff with retries and a maximum delay to handle temporary API outages.

Usage:

    $ COMMAND polling_delay_seconds max_stacks_delay_seconds recovery_delay_seconds shell_command...

    OR

    $ COMMAND -c /path/to/config_file

Options:

    polling_delay_seconds: The time interval between checking the time difference,
        in seconds.
    max_stacks_delay_seconds: The maximum acceptable time difference between
        Stacks and Bitcoin blocks, in seconds.
    recovery_delay_seconds: The delay after executing the shell command before
        resuming monitoring, in seconds.
    shell_command: The shell command to execute when the time difference exceeds
        the threshold.

Alternatively, you can provide a configuration file using the -c option.
The configuration file should be a JSON file with the following fields:

```json
{
    "polling_delay_seconds": <int>,
    "max_stacks_delay_seconds": <int>,
    "recovery_delay_seconds": <int>,
    "shell_command": <list[str]>
}
```

Example:
```json
{
  "polling_delay_seconds": 60,
  "max_stacks_delay_seconds": 60,
  "recovery_delay_seconds": 60,
  "shell_command": ["echo", "hello, world!"],
}
```
"""

import toml
import json
import requests
import time
from backoff_utils import strategies
from backoff_utils import apply_backoff
from datetime import datetime
from sys import argv
import subprocess

# Stacks API endpoints.
API_URL_LATEST_STACKS_BLOCK = "https://api.mainnet.hiro.so/extended/v1/block?limit=1"
API_URL_LATEST_STACKS_TRANSACTION = "https://api.mainnet.hiro.so/extended/v1/tx/{transaction_id}"

# Bitcoin API endpoints.
API_URL_LATEST_BTC_BLOCK_HASH = "https://mempool.space/api/blocks/tip/hash"
API_URL_BTC_BLOCK_FROM_HASH = "https://mempool.space/api/block/{block_hash}"

@apply_backoff(
    strategy=strategies.Exponential,
    catch_exceptions=(RuntimeError,),
    max_tries=3,
    max_delay=60,
)
def get_from_api(api_url: str) -> dict:
    """
    Sends a GET request to the specified API URL and returns the string response.

    Args:
        api_url (str): The URL of the API endpoint to call.

    Returns:
        dict: The string response data.

    Raises:
        RuntimeError: If the API call fails or the response cannot be parsed as JSON.
    """

    try:
        # Make a GET request to the API endpoint
        response = requests.get(api_url)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the response and return the data
            return response.text

    except Exception as e:
        # If an exception occurs, raise a RuntimeError
        raise RuntimeError("Failed to unpack JSON.")

    # If the code reaches this point, it means the API call failed.
    raise RuntimeError("Failed to get response.")


def get_latest_bitcoin_block_timestamp() -> int:
    """
    Retrieves the timestamp of the latest Bitcoin block.

    Returns:
        int: The timestamp of the latest Bitcoin block.
    """

    latest_btc_block_hash = get_from_api(API_URL_LATEST_BTC_BLOCK_HASH)
    json_response = json.loads(get_from_api(
        API_URL_BTC_BLOCK_FROM_HASH.format(block_hash=latest_btc_block_hash)))
    return json_response["timestamp"]


def get_latest_stacks_block_timestamp() -> int:
    """
    Retrieves the timestamp of the latest Stacks block.

    Returns:
        int: The timestamp of the latest Stacks block.
    """

    latest_stacks_block_json = json.loads(get_from_api(API_URL_LATEST_STACKS_BLOCK))
    return latest_stacks_block_json["results"][0]["burn_block_time"]

def stacks_block_delay_event_listener(
    polling_delay_seconds: int,
    max_stacks_delay_seconds: int,
    recovery_delay_seconds: int,
    shell_command: list[str],
):
    """
    Continuously monitors the time between Stacks blocks and Bitcoin blocks.

    If the time difference exceeds a specified threshold, the script executes
    a user-defined shell command. The script utilizes exponential backoff with
    retries and a maximum delay to handle temporary API outages.

    Args:
        polling_delay_seconds (int): The time interval between checking the
            time difference, in seconds (default: 60).
        max_stacks_delay_seconds (int): The maximum acceptable time difference
            between Stacks and Bitcoin blocks, in seconds (default: 60).
        recovery_delay_seconds (int): The delay after executing the shell
            command before resuming monitoring, in seconds (default: 60).
        shell_command (list[str]): The shell command to execute when the time
            difference exceeds the threshold (default: ["echo", "hello"]).
    """

    while True:

        # Continuously retrieve the timestamps of the latest Stacks and Bitcoin blocks.
        latest_stacks_block_timestamp = get_latest_stacks_block_timestamp()
        latest_bitcoin_block_timestamp = get_latest_bitcoin_block_timestamp()

        # Calculate the time difference between the latest Stacks and Bitcoin blocks.
        stacks_block_delay = datetime.fromtimestamp(latest_bitcoin_block_timestamp) - \
            datetime.fromtimestamp(latest_stacks_block_timestamp)

        # If the time difference exceeds the specified threshold execute the shell command.
        if stacks_block_delay.seconds > max_stacks_delay_seconds:
            print(f"Delay between stacks and bitcoin block: {stacks_block_delay}")
            print(f"$ {' '.join(shell_command)}")

            subprocess.run(shell_command, shell=True)
            time.sleep(recovery_delay_seconds) # Wait for the recovery period before resuming monitoring.

        # If the time difference is within the acceptable range wait for the polling interval.
        else:
            time.sleep(polling_delay_seconds)

def read_config(config_location: str):
    """
    Reads and returns the contents of a configuration file.
    """
    with open(config_location, "r") as config_file:
        return json.load(config_file)

def main():
    """
    Continuously monitors the time between Stacks blocks and Bitcoin blocks,
    triggering an event when thresholds are exceeded.

    If the time difference exceeds a specified threshold, the script executes
    a user-defined shell command. It utilizes exponential backoff with
    retries and a maximum delay to handle temporary API outages.
    """

    try:
        configuration = {}

        if len(argv) == 1:
            configuration = read_config("./config/stacks-block-delay-event-trigger.json")
        elif "-c" in argv:
            # Load configuration from specified file
            config_location = argv[argv.index("-c") + 1]
            configuration = read_config(config_location)

        else:
            # Load configuration from command-line arguments
            configuration = {
                "polling_delay_seconds": int(argv[1]),
                "max_stacks_delay_seconds": int(argv[2]),
                "recovery_delay_seconds": int(argv[3]),
                "shell_command": argv[4:],
            }

        stacks_block_delay_event_listener(**configuration)

    # Print usage if there are errors.
    except Exception as e:
        print(f"Failed to run {argv[0]}")
        print(f"\n\t$ COMMAND polling_delay_seconds max_stacks_delay_seconds recovery_delay_seconds shell_command...")
        print("\t\tOR")
        print(f"\t$ COMMAND -c /path/to/config_file.json\n")
        print(f"Error: {e}")

# Execute main.
if __name__ == "__main__":
    main()