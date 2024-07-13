# Use the official Python image from the Docker Hub
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install the required packages
RUN pip install -r requirements.txt

# Expose port 8501
EXPOSE 8501

# Command to run the Streamlit app
CMD ["streamlit", "run", "app.py"]
