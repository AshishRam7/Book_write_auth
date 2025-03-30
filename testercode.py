import requests
import json
import os # To potentially load from .env if you prefer later

# --- Configuration ---
# IMPORTANT: Replace 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx' with your ACTUAL Qwen API Key
API_KEY = "sk-d10d31971a4d432cbee3556119cb1013"

API_ENDPOINT_URL = "https://dashscope-intl.aliyuncs.com/api/v1/services/aigc/text-generation/generation" # <--- CORRECTED ENDPOINT
MODEL = "qwen-plus"

# --- Request Details (Mimicking Go Code) ---
# You can change these if needed for testing
book_title = "Test Book Title"
book_description = "A simple test description."
num_chapters = 3

# Construct the prompts similar to the Go code
system_prompt = f"""You are a professional book writer.
Generate a complete book with the following details:
- Title: {book_title}
- Description: {book_description}
- Number of chapters: {num_chapters}

The book should have a coherent narrative that follows the description.
Each chapter should have a title (e.g., using '## Chapter Title') and substantial content.
Format the output using standard Markdown.
Create a compelling opening and satisfying conclusion. Ensure the full book text is generated."""

user_prompt = f"Please generate the complete book titled '{book_title}' with {num_chapters} chapters based on the provided description."

# --- Construct Payload ---
payload = {
    "model": MODEL,
    "input": {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ]
    },
    "result_format": "message"
}

# --- Construct Headers ---
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer sk-d10d31971a4d432cbee3556119cb1013"
}

# --- Make the API Request ---
print(f"Sending request to: {API_ENDPOINT_URL}")
print(f"Using model: {MODEL}")
# print(f"Payload: {json.dumps(payload, indent=2)}") # Uncomment to see full payload
print("-" * 20)

try:
    # Set a timeout (in seconds), similar to the Go code's context timeout
    timeout_seconds = 300
    response = requests.post(
        API_ENDPOINT_URL,
        headers=headers,
        json=payload, # requests library handles json encoding
        timeout=timeout_seconds
    )

    # --- Process Response ---
    print(f"Response Status Code: {response.status_code}")
    print("-" * 20)

    if response.status_code == 200:
        try:
            response_data = response.json()
            print("Response JSON Data:")
            print(json.dumps(response_data, indent=2))

            # Extract text if available
            try:
                 generated_text = response_data.get("output", {}).get("text", "")
                 finish_reason = response_data.get("output", {}).get("finish_reason", "N/A")
                 print("\n--- Generated Text ---")
                 print(f"(Finish Reason: {finish_reason})")
                 print(generated_text)
                 print("--- End Generated Text ---")
            except Exception as e:
                print(f"\nError extracting text from successful response: {e}")

        except json.JSONDecodeError:
            print("Error: Could not decode JSON response, even though status code was 200.")
            print("Raw Response Text:")
            print(response.text)
    else:
        # Print error details if status code is not OK
        print("Error: API call failed.")
        print("Raw Response Text:")
        # Try to print JSON if possible, otherwise raw text
        try:
            error_data = response.json()
            print(json.dumps(error_data, indent=2))
        except json.JSONDecodeError:
            print(response.text) # Print raw text if not JSON

except requests.exceptions.Timeout:
    print(f"Error: Request timed out after {timeout_seconds} seconds.")
except requests.exceptions.RequestException as e:
    print(f"Error: An error occurred during the request: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")