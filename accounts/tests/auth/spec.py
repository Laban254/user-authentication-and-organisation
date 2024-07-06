from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
import jwt
from django.utils import timezone
from django.conf import settings
import pytz

User = get_user_model()

class TokenGenerationTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='testuser@example.com',
            password='testpassword',
            firstName='Test',
            lastName='User',
            phone='+1234567890'
        )
        print("Setup: Created user with email 'testuser@example.com'")

    def test_token_generation(self):
        # Attempt to log in and get a token
        response = self.client.post(reverse('token_obtain_pair'), {
            'email': 'testuser@example.com',
            'password': 'testpassword',
        })
        print(f"Login response status code: {response.status_code}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Extract the access token from the response
        access_token = response.data.get('access')
        print(f"Access token: {access_token}")

        # Proceed only if an access token was successfully obtained
        if access_token:
            # Decode the token to check its payload
            decoded_token = jwt.decode(access_token, settings.SECRET_KEY, algorithms=['HS256'])
            print(f"Decoded token: {decoded_token}")

            # Assert the user ID in the token matches the user's ID
            self.assertEqual(decoded_token['user_id'], self.user.userId)
            print(f"User ID in token: {decoded_token['user_id']}")

            # Convert the exp timestamp to a datetime object and make it offset-aware
            exp_datetime = datetime.fromtimestamp(decoded_token['exp'], pytz.utc)
            print(f"Token expiration time: {exp_datetime}")

            # Assert the token has not expired
            now = timezone.now()
            self.assertGreaterEqual(exp_datetime, now)
            print(f"Current time: {now}")

            # Assert the token contains the correct user details
            self.assertEqual(decoded_token['email'], 'testuser@example.com')
            self.assertEqual(decoded_token['firstName'], 'Test')
            self.assertEqual(decoded_token['lastName'], 'User')
            self.assertEqual(decoded_token['phone'], '+1234567890')
            print("Token contains the correct user details")
        else:
            print("Access token not found in response")