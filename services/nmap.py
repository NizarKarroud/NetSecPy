import subprocess

class NmapCMD :
    def __init__(self) -> None:
        pass

    def run(self, command:list):
        try:

            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"Error running script: {result.stderr}")
            else:

                return result.stdout

        except Exception as e:
            return str(e)