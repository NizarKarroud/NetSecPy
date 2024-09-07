import subprocess

class NmapCMD :
    def __init__(self) -> None:
        pass

    def run(self, command:list):
        try:

            # Run the command and capture the output
            result = subprocess.run(command, capture_output=True, text=True)

            # Check for errors
            if result.returncode != 0:
                print(f"Error running script: {result.stderr}")
            else:
                # Print the output of the scan
                return result.stdout

        except Exception as e:
            return str(e)