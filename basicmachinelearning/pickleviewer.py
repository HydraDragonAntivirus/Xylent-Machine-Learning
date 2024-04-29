import joblib

def show_pickle_contents(file_path):
    try:
        # Load the pickle file
        model = joblib.load(file_path)
        
        # Display the model attributes
        print("Model attributes:")
        for attr in dir(model):
            if not attr.startswith('_'):
                print(attr, getattr(model, attr))

    except FileNotFoundError:
        print("File not found.")

# Get the path to the pickle file from the user
pickle_file_path = input("Enter the path to the pickle file: ")

# Display the full content of the pickle file
show_pickle_contents(pickle_file_path)