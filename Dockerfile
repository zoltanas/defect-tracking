# Use an official Python runtime as a parent image
FROM python:3.9-slim-bullseye

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required by WeasyPrint and pdf2image
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    poppler-utils \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Find the pango library path and store it for the entrypoint
RUN dpkg -L libpango-1.0-0 | grep 'libpango-1.0.so.0$' | xargs dirname > /library_path.txt

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application source code
COPY . .

# Make the entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Set the entrypoint for the container
ENTRYPOINT ["/app/entrypoint.sh"]
