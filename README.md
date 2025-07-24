# Data Access Tracker

An internal web application built with Flask for logging and tracking data access. This tool helps with data governance and accountability for audits by recording who accessed which dataset, when, and for what purpose.

## Features

* **User Login (Placeholder):** For this version, basic username input is used. A full authentication system would be added for production.
* **Dataset Selection:** Users can specify the dataset name they accessed.
* **Access Log Entry:** Simple form to log access details.
* **Access History View:** Displays all logged access entries, filterable by user/date (future enhancement).

## Project Structure
├── app.py                   # Main application entry point
├── requirements.txt         # All necessary Python packages
├── /templates/              # HTML files (e.g., index.html, result.html)
│   └── layout.html          # Base template with common layout
│   └── index.html           # Home page
│   └── log_access.html      # Form to log access
│   └── access_history.html  # View of all access logs
├── /static/                 # CSS, JS, images
│   └── style.css            # Custom styles
├── /utils/                  # Helper functions
│   └── prompt_helper.py     # Placeholder for AI logic (not implemented in this version)
├── config.py                # App configuration settings
├── README.md                # Project overview, setup instructions
└── .gitignore               # Ignore unnecessary files


## Setup and Running the Application

### Prerequisites

* Python 3.8+

### Installation

1.  **Clone this repository (if applicable) or navigate to your project directory.**
    ```bash
    cd data-access-tracker
    ```
2.  **Create and activate a virtual environment:**
    * **macOS/Linux:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    * **Windows (Command Prompt):**
        ```bash
        py -m venv venv
        venv\Scripts\activate.bat
        ```
    * **Windows (PowerShell):**
        ```powershell
        py -m venv venv
        .\venv\Scripts\Activate.ps1
        ```
3.  **Install the required Python packages:**
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

1.  **Ensure your virtual environment is active.**
2.  **Run the Flask application:**
    ```bash
    python app.py
    ```
3.  **Open your web browser** and go to `http://127.0.0.1:5000/` (or the address shown in your terminal).

## Database

This application uses SQLite for data storage. The database file `data_access_tracker.db` will be created automatically in your project root when you run `app.py` for the first time.

## Future Enhancements

* User authentication and authorization.
* Filtering and searching access history by user, dataset, and date range.
* Improved UI/UX with a CSS framework (e.g., Bootstrap or Tailwind CSS).
* Exporting access logs.
* Integration with AI for advanced analytics or anomaly detection (using `utils/prompt_helper.py`)