# Dockerfile

# ---- Stage 1: Build ----
# Use Python 3.9 on Debian Bullseye for access to newer system libraries like Pango.
FROM python:3.9-slim-bullseye AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Install system-level dependencies.
# WeasyPrint needs Pango, Cairo, GDK-PixBuf, FFI.
# pdf2image needs poppler-utils.
# psycopg2-binary needs libpq-dev and build-essential for potential compilation.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    # For WeasyPrint & Pango >= 1.44
    libcairo2-dev \
    libpango1.0-dev \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    shared-mime-info \
    # For pdf2image
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# Copying requirements.txt first leverages Docker's layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Stage 2: Final Image ----
FROM python:3.9-slim-bullseye

WORKDIR /app

# The www-data user and group are expected to exist in the base python:3.9-slim-bullseye image.

# Install runtime system dependencies in the final stage.
# These are typically the non-dev versions of libraries needed by Python packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi7 \
    shared-mime-info \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.9/site-packages/ /usr/local/lib/python3.9/site-packages/
# Copy any compiled binaries/scripts installed by pip (if any were placed in /usr/local/bin)
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy your application code into the container
COPY . .

# Create application directories and set permissions
RUN mkdir -p /app/instance \
             /app/static/images/thumbnails \
             /app/static/images/report_temp \
             /app/static/drawings \
             /app/reports \
             /app/static/product_documentation && \
    chown -R www-data:www-data /app

# Switch to the non-root user
USER www-data

# Expose the port the app runs on
EXPOSE 8000

# The command to run your application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]