"""
Script to continuously update the `satoshis_per_byte` value in a TOML file with the
mean fee estimate from a list of API endpoints.

Usage:
    $ COMMAND /path/to/miner.toml polling_delay_seconds

Args:
    toml_file_location (str): The path to the TOML file to update.
    polling_delay_seconds (int): The frequency in seconds to check for fee updates.
"""

import toml
import json
import requests
import time
from backoff_utils import strategies
from backoff_utils import apply_backoff
from sys import argv

# Fee estimation API URLS and their corresponding fee extraction functions.
# At least one of these needs to be working in order for the script to function.
FEE_ESTIMATIONS = [
    # Bitcoiner Live API
    (
        'https://bitcoiner.live/api/fees/estimates/latest?confidence=0.9',
        lambda response_json: response_json["estimates"]["30"]["sat_per_vbyte"],
    ),

    # Mempool Space API
    (
        'https://mempool.space/api/v1/fees/recommended',
        lambda response_json: response_json["halfHourFee"],
    ),

    # Blockchain.info API
    (
        'https://api.blockchain.info/mempool/fees',
        lambda response_json: response_json["regular"],
    ),
]

def calculate_fee_estimate():
    """
    Calculates the mean fee estimate from a list of API URLs
    and their corresponding fee extraction functions.

    Args:
        FEE_ESTIMATIONS (list): A list of tuples, where each tuple
        contains the URL of an API endpoint and a function that extracts
        the fee estimate from the JSON response.

    Returns:
        int: The mean fee estimate in sat/Byte.

    Raises:
        None
    """

    # Gather all API estimated fees in sat/Byte
    estimated_fees = []
    for api_url, unpack_fee_estimate in FEE_ESTIMATIONS:

        try:
            json_response = json.loads(get_from_api(api_url))
            estimated_fee = unpack_fee_estimate(json_response)
            estimated_fees.append(estimated_fee)

        except Exception as e:
            pass

    # Calculate the mean fee estimate
    mean_fee = int(sum(estimated_fees) / len(estimated_fees))

    return mean_fee

@apply_backoff(
    strategy=strategies.Exponential,
    catch_exceptions=(RuntimeError,),
    max_tries=3,
    max_delay=60,
)
def get_from_api(api_url: str) -> str:
    """
    Sends a GET request to the specified API URL and returns the string response.

    Args:
        api_url (str): The URL of the API endpoint to call.

    Returns:
        dict: The string response data.

    Raises:
        RuntimeError: If the API call fails.
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


def update_config_fee(toml_file_location: str, polling_delay_seconds: int):
    """
    Updates the `satoshis_per_byte` value in the specified TOML file
    with the mean fee estimate from a list of API endpoints.

    Args:
        toml_file_location (str): The path to the TOML file to update.

    Raises:
        IOError: If the TOML file cannot be read or written.
        RuntimeError: If the fee estimation process fails.
    """

    while True:
        # Calculate mean fee estimate from the list of APIs
        fee_estimate = calculate_fee_estimate()

        # Read toml file data
        with open(toml_file_location, 'r') as toml_file:
            toml_data = toml.load(toml_file)

        # Update satoshis_per_byte data
        toml_data["burnchain"]["satoshis_per_byte"] = fee_estimate

        # Update toml file with configuration changes
        with open(toml_file_location, 'w') as toml_file:
            toml.dump(toml_data, toml_file)

        time.sleep(polling_delay_seconds)

def read_config(config_location: str):
    """
    Reads and returns the contents of a configuration file.
    """
    with open(config_location, "r") as config_file:
        return json.load(config_file)

def main():
    """
    Continuously updates the `satoshis_per_byte` value in the specified
    TOML file with the mean fee estimate from a list of API endpoints.

    Usage:
        $ {argv[0]} /path/to/miner.toml polling_delay
    """

    try:
        configuration = {}

        if len(argv) == 1:
            configuration = read_config("./config/fee-estimate.json")
        elif "-c" in argv:
            # Load configuration from specified file
            config_location = argv[argv.index("-c") + 1]
            configuration = read_config(config_location)
        else:
            # Load configuration from command-line arguments
            configuration = {
                "toml_file_location": argv[1],
                "polling_delay_seconds": int(argv[2]),
            }

        update_config_fee(**configuration)

    # Print usage if there are errors.
    except Exception as e:
        print(f"Failed to run {argv[0]}")
        print(f"\n\t$ COMMAND /path/to/miner.toml polling_delay_seconds")
        print("\t\tOR")
        print(f"\t$ COMMAND -c /path/to/config_file.json\n")
        print(f"Error: {e}")

# Execute main.
if __name__ == "__main__":
    main()