# Defect Tracking Application

This is a Flask-based web application for tracking defects in projects.

## Deployment

This application is configured for deployment on [Firebase Studio](https://firebase.google.com/docs/studio), which uses [Nixpacks](https://nixpacks.com/) to build and deploy the application.

### Configuration

The deployment is configured using the `nixpacks.toml` file. This file specifies the system dependencies, build commands, and the start command for the application.

### System Dependencies

The application requires the following system dependencies, which are installed via Nixpacks:

*   **Pango**: For text rendering in PDF generation.
*   **Cairo**: A 2D graphics library.
*   **GDK-PixBuf**: An image loading library.
*   **libffi**: A foreign function interface library.
*   **Poppler**: A PDF rendering library, used by `pdf2image`.
*   **glib**: Core application building blocks for libraries and applications written in C.

These are specified in the `[phases.setup.nixPkgs]` section of the `nixpacks.toml` file.

### Database Migrations and Start Command

The start command in the `nixpacks.toml` file handles database migrations and starts the application. It first runs `flask init-db` to initialize the database schema, and then starts the application using `gunicorn`.

```
[start]
cmd = "flask init-db && gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app"
```

The `$PORT` environment variable is automatically provided by the Firebase Studio environment.

## Local Development

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Set Environment Variables**:
    Create a `.env` file and set the necessary environment variables, such as `SQLALCHEMY_DATABASE_URI`.

3.  **Initialize the Database**:
    ```bash
    flask init-db
    ```

4.  **Run the Application**:
    ```bash
    flask run
    ```
