# Image Sharing Web App

A simple web application for securely sharing images with password protection.

## Features

- Password-protected admin area
- Upload multiple images at once
- Set custom passwords for each image share
- Generate unique URLs for sharing
- Manage uploaded images and shares
- Minimal and clean shared image viewing page

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python run.py
   ```

3. Access the admin area:
   - URL: http://localhost:5000/login
   - Default credentials: 
     - Username: admin
     - Password: admin

## Usage

1. Log in to the admin area
2. Upload images and set a password
3. Share the generated URL with friends
4. Friends can view images by entering the password

## Security Note

For production use, please change the default admin password and set a proper SECRET_KEY environment variable.