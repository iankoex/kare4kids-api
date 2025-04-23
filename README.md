# kare4kids-api
Babysitting App – Backend (Django + DRF)

The Babysitting App Backend is a robust RESTful API built with Django and Django REST Framework, designed to power a secure and user-friendly babysitting platform connecting parents with reliable sitters.

It provides all the core logic, database interactions, and authentication necessary to manage users, bookings, job tracking, and payments — including M-Pesa mobile payments integration for seamless financial transactions in the Kenyan market.

Key Features

Custom User Authentication
Supports both parents and sitters with role-based permissions using JWT tokens via SimpleJWT.

Job & Booking Management
Parents can book sitters, while sitters can accept, decline, or complete jobs. Status updates are handled efficiently with clear job lifecycle transitions.

Payment Integration (M-Pesa)
Integrated with Safaricom's STK Push API via sandbox and production setups. Parents can securely pay for completed jobs, with real-time callback handling and status updates.

RESTful API Endpoints
Clean, versioned API structure for frontend consumption and third-party integration.

Security & Validation
CSRF protection, token-based authentication, role checks, and proper validation ensure a secure backend.


 Tech Stack
 
Backend Framework: Django, Django REST Framework

Auth: JWT (SimpleJWT)

Database: PostgreSQL (hosted on Tembo)

Payment Gateway: M-Pesa (Safaricom STK Push)

Dev Tools: Ngrok for local testing, Docker-ready configuration for deployment

Environment Configuration

Sensitive credentials (e.g., database URL, API keys) are managed via environment variables or a .env file to ensure security in production environments.
