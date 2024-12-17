# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 80 available to the world outside the container (optional, depends on your use case)
EXPOSE 80

# Run the script when the container launches
CMD ["python", "master.py"]
