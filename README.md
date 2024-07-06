# Django User Management API

This Django project implements a user management system with authentication and organization management using Django REST Framework.

## Installation

### Using Docker (Recommended)

1.  Clone the repository:
    
    
    `git clone git@github.com:Laban254/user-authentication-and-organisation.git
    cd user-authentication-and-organisation` 
    
2.  Build and run Docker containers:

    
    `docker-compose up --build` 
    
3.  Apply database migrations:
    
   
    
    `docker-compose exec web python manage.py migrate` 
    
4.  The application will be accessible at `http://localhost:8000`.
    

### Normal Setup

1.  Clone the repository:
    

    
    `git clone git@github.com:Laban254/user-authentication-and-organisation.git
    cd user-authentication-and-organisation` 
    
2.  Install dependencies:

    
    `pip install -r requirements.txt` 
    
3.  Apply database migrations:
    
  
    
    `python manage.py migrate` 
    
4.  Run the development server:
    
 
    
    `python manage.py runserver` 
    
5.  The application will be accessible at `http://localhost:8000`.
    

## Endpoints

### User Registration

-   **POST /auth/register/**
    
    Registers a new user and creates a default organization.
    
    Request Body:
    

    
    `{
      "firstName": "string",
      "lastName": "string",
      "email": "string",
      "password": "string",
      "phone": "string"
    }` 
    
    Successful Response:
    

    
    `{
      "status": "success",
      "message": "Registration successful",
      "data": {
        "accessToken": "eyJh...",
        "user": {
          "userId": "string",
          "firstName": "string",
          "lastName": "string",
          "email": "string",
          "phone": "string"
        }
      }
    }` 
    

### User Login

-   **POST /auth/login/**
    
    Logs in a user with valid credentials.
    
    Request Body:

    
    `{
      "email": "string",
      "password": "string"
    }` 
    
    Successful Response:
    

    
    `{
      "status": "success",
      "message": "Login successful",
      "data": {
        "accessToken": "eyJh...",
        "user": {
          "userId": "string",
          "firstName": "string",
          "lastName": "string",
          "email": "string",
          "phone": "string"
        }
      }
    }` 
    

### User Detail

-   **GET /api/users/int:id/**
    
    Retrieves the details of a specific user.
    
    Successful Response:

    
    `{
      "status": "success",
      "message": "User details retrieved",
      "data": {
        "userId": "string",
        "firstName": "string",
        "lastName": "string",
        "email": "string",
        "phone": "string"
      }
    }` 
    

### Organisation List

-   **GET /api/organisations/**
    
    Retrieves a list of organizations the logged-in user belongs to or created.
    
    Successful Response:

    
    `{
      "status": "success",
      "message": "Organisations retrieved",
      "data": {
        "organisations": [
          {
            "orgId": "string",
            "name": "string",
            "description": "string"
          }
        ]
      }
    }` 
    

### Organisation Detail

-   **GET /api/organisations/int:orgId/**
    
    Retrieves the details of a specific organization.
    
    Successful Response:
    

    
    `{
      "status": "success",
      "message": "Organisation details retrieved",
      "data": {
        "orgId": "string",
        "name": "string",
        "description": "string"
      }
    }` 
    

### Organisation Create

-   **POST /api/organisationsCreate/**
    
    Creates a new organization.
    
    Request Body:

    
    `{
      "name": "string",
      "description": "string"
    }` 
    
    Successful Response:
    

    
    `{
      "status": "success",
      "message": "Organisation created successfully",
      "data": {
        "orgId": "string",
        "name": "string",
        "description": "string"
      }
    }` 
    

### Add User to Organisation

-   **POST /api/organisations/int:orgId/users/**
    
    Adds a user to a specific organization.
    
    Request Body:

    
    `{
      "userId": "string"
    }` 
    
    Successful Response:
    

    
    `{
      "status": "success",
      "message": "User added to organisation successfully"
    }` 
    

### Token Obtain

-   **POST /api/token/**
    
    Obtain JWT token for authentication.
    
    Request Body:

    
    `{
      "username": "string",
      "password": "string"
    }` 
    
    Successful Response:
    

    
    `{
      "access": "string",
      "refresh": "string"
    }` 
    

## Test Cases
To run test, be in the same directory as manage.py and run

		python3 manage.py  test  accounts.tests.auth.spec

-   **auth.spec.py**

    
    Contains unit tests and end-to-end tests for:
    
    -   Successful user registration
    -   Successful user login
    -   Validation errors for missing fields
    -   Duplicate email or userID errors
    -   Token generation and expiration checks
    -   Access control for organizations

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

For any questions or inquiries, please contact:

-   **Laban254** - [GitHub](https://github.com/Laban254)
