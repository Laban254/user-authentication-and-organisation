from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
import jwt
from django.utils import timezone
from django.conf import settings
import pytz
from accounts.models import Organisation
from rest_framework.test import APIClient


User = get_user_model()

class TokenGenerationTest(APITestCase):
    """
    Test case for token generation and user details validation.
    """
    def setUp(self):
        """
        Set up a user for testing token generation.
        """
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpassword',
            firstName='Test',
            lastName='User',
            phone='+1234567890'
        )

    def test_token_generation_and_user_details(self):
        """
        Test token generation and validate user details in the token.
        """
        response = self.client.post(reverse('token_obtain_pair'), {
            'email': 'testuser@example.com',
            'password': 'testpassword',
        })


        self.assertEqual(response.status_code, status.HTTP_200_OK)

        access_token = response.data.get('access')

        if access_token:
            decoded_token = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
            self.assertEqual(decoded_token['user_id'], self.user.userId)
            exp_datetime = datetime.fromtimestamp(decoded_token['exp'], pytz.utc)
            now = timezone.now()
            self.assertGreaterEqual(exp_datetime, now)

            self.assertEqual(decoded_token['email'], 'testuser@example.com')
            self.assertEqual(decoded_token['firstName'], 'Test')
            self.assertEqual(decoded_token['lastName'], 'User')
            self.assertEqual(decoded_token['phone'], '+1234567890')
        else:
            print("Access token not found in response")

class OrganisationAccessTestCase(APITestCase):
    """
    Test case for verifying user access permissions to organisations.
    """
    def setUp(self):
        """
        Set up users and organisations for testing access permissions.
        """
        # Create users
        self.user1 = User.objects.create_user(
            email='user1@example.com',
            password='testpassword1',
            firstName='User',
            lastName='One',
            phone='+1234567891'
        )
        self.user2 = User.objects.create_user(
            email='user2@example.com',
            password='testpassword2',
            firstName='User',
            lastName='Two',
            phone='+1234567892'
        )

        # Create organisations
        self.org1 = Organisation.objects.create(
            name="Organisation One",
            description="Description for org one"
        )
        self.org2 = Organisation.objects.create(
            name="Organisation Two",
            description="Description for org two"
        )

        # Associate users with organisations
        self.org1.users.add(self.user1)
        self.org2.users.add(self.user2)

    def test_user_cannot_access_unauthorized_organisation(self):
        """
        Test that a user cannot access an organisation they are not authorized for.
        """
        # Log in user1 to get the access token
        client = APIClient()
        login_response = client.post(reverse('token_obtain_pair'), {
            'email': 'user1@example.com',
            'password': 'testpassword1',
        })

        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        
        access_token = login_response.data['access']
        
        # Authenticate with the access token
        client.credentials(HTTP_AUTHORIZATION='Bearer ' + access_token)
        
        # Attempt to access data from org2 as user1
        response = client.get(reverse('organisation-detail', args=[self.org2.pk]))
        
        # Check if access is denied
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)



class RegisterEndpointTestCase(APITestCase):
    """
    Test case for registration endpoint.
    """
    
    url = reverse('register')

    def test_successful_registration(self):
        """
        Test successful user registration.
        """
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'testpassword',
            'phone': '+1234567890'
        }

        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email='john.doe@example.com')
        self.assertEqual(user.firstName, 'John')
        self.assertEqual(user.lastName, 'Doe')

    def test_unique_email_constraint(self):
        """
        Test that registration fails with a duplicate email.
        """
        data1 = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'testpassword',
            'phone': '+25479620088'
        }
        data2 = {
            'firstName': 'Jane',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'testpassword',
            'phone': '+25479620088'
        }

        response1 = self.client.post(self.url, data1, format='json')
        self.assertEqual(response1.status_code, status.HTTP_201_CREATED)

        response2 = self.client.post(self.url, data2, format='json')
        self.assertEqual(response2.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_required_fields(self):
        """
        Test registration fails when required fields are missing.
        """
        data = {
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'testpassword'
        }

        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('firstName', response.data['errors'][0]['field'])

    def test_invalid_email_format(self):
        """
        Test registration fails with an invalid email format.
        """
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'invalid-email-format',  # Invalid email format
            'password': 'testpassword'
        }

        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data['errors'][0]['field'])

    def test_blank_password(self):
        """
        Test registration fails with a blank password.
        """
        data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'john.doe@example.com',
            'password': '',  # Blank password
        }

        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('password', response.data['errors'][0]['field'])
