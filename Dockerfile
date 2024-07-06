# Use an official Python runtime as a parent image
# Use an official Python runtime as a parent image
FROM python:3.10

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /code

# Install Python dependencies
COPY requirements.txt /code/
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy the rest of the application code
COPY . /code/

# Expose the port on which Gunicorn will run
EXPOSE $PORT

# Run Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "user_auth_org.wsgi:application"]