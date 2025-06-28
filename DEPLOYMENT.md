# Deployment Guide

This document provides guidance for deploying the Defect Tracker application, with a focus on system dependencies.

## System Dependencies

The application relies on certain system-level packages for full functionality, especially for PDF generation and processing.

### 1. Poppler

**Why it's needed:**
The `pdf2image` Python library, used for converting PDF pages into images (e.g., for creating thumbnails of PDF attachments or rendering PDF drawing pages to mark defects), is a wrapper around Poppler PDF rendering library utilities (`pdftoppm`, `pdfinfo`, etc.).

**Installation:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install -y poppler-utils
    ```

*   **Alpine Linux (common in Docker containers):**
    ```bash
    apk add --no-cache poppler-utils
    ```

*   **Fedora/CentOS/RHEL:**
    ```bash
    sudo dnf install -y poppler-utils
    ```

*   **macOS (using Homebrew):**
    ```bash
    brew install poppler
    ```

**Environment Variable `POPPLER_PATH`:**
If Poppler is installed in a non-standard location (common in some container setups or when using manually compiled versions), you may need to set the `POPPLER_PATH` environment variable to the directory containing the Poppler binaries (e.g., `/usr/local/poppler/bin` if `pdftoppm` is at `/usr/local/poppler/bin/pdftoppm`).

The application will first check this environment variable. If not set or if Poppler is not found at the specified path, it will attempt to find Poppler utilities in the system's `PATH`.

Example for Dockerfile:
```dockerfile
# For Debian/Ubuntu based images
RUN apt-get update && apt-get install -y poppler-utils && rm -rf /var/lib/apt/lists/*

# For Alpine based images
RUN apk add --no-cache poppler-utils

# If installing to a custom location and needing POPPLER_PATH:
# ENV POPPLER_PATH=/path/to/your/poppler/bin
```

### 2. WeasyPrint Dependencies

**Why it's needed:**
WeasyPrint is used to generate PDF reports from HTML templates. It has its own set of dependencies for rendering, including libraries for fonts, SVG, and various image formats.

**Common Dependencies:**
While WeasyPrint's documentation is the definitive source, common dependencies include:
*   Pango
*   Cairo
*   libffi
*   GDK-PixBuf (for image format support beyond PNG)

**Installation (Debian/Ubuntu example for WeasyPrint and its typical dependencies):**
```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```
Note: Some of these might already be installed if you're using a Python base image. The `poppler-utils` from above is separate. Refer to the official WeasyPrint installation guide for the most up-to-date and comprehensive list for your specific OS.

## Application Configuration

Ensure all necessary environment variables for the application are set (e.g., database connection strings, secret keys, mail server settings). Refer to the application's main configuration section in `app.py` or any `.env.example` file if provided.

## Running the Application

For production, it's recommended to use a WSGI server like Gunicorn (which is included in `requirements.txt`).

Example Gunicorn command:
```bash
gunicorn --workers 4 --bind 0.0.0.0:5000 app:app
```
Adjust `workers` and `bind` address/port as needed for your environment.
Ensure the `PYTHONPATH` is set up correctly if your application structure requires it, or run Gunicorn from the project's root directory.
```
