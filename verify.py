
from datetime import datetime

def display_status():
    name = "Emmanuel O. Akingbasote"
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Python is ready for Cybersecurity!"

    print("=" * 50)
    print(f"Name: {name}")
    print(f"Date: {current_date}")
    print(f"Status: {status}")
    print("=" * 50)

# Run the function
display_status()
