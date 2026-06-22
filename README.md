# LifeDrop Server

This is the backend/API server for the LifeDrop blood donation platform. It handles users, JWT verification, donation requests, dashboard statistics, funding records, and Stripe checkout payment flow.

The backend is built with Express.js and MongoDB. It is deployed separately from the Next.js frontend.

## Live URL

Backend Live API:
https://lifedrop-server-two.vercel.app

Frontend Live Site:
https://lifedrop-client.vercel.app

Health Check:
https://lifedrop-server-two.vercel.app/api/health

## Project Purpose

The purpose of this backend is to provide API support for the LifeDrop blood donation platform.

It stores user data, donation requests, funding records, and protects private APIs using JWT token verification. It also handles role-based access for donor, volunteer, and admin users.

## Key Features

* Express.js REST API
* MongoDB Atlas database connection
* Better Auth user/session data support
* JWT token generation
* JWT token verification middleware for private APIs
* Role-based API protection
* Admin-only routes
* Volunteer/Admin protected routes
* Donor donation request APIs
* Public donor search API
* Public pending donation request API
* Dashboard statistics API
* User management API for admin
* Funding API
* Stripe checkout session creation
* Stripe payment success verification
* Production CORS setup
* JSON 404 handler
* Global error handler
* Health check API for production testing

## Main API Features

### Auth and JWT

* Create JWT token after login/signup
* Verify JWT token before allowing private API access
* Blocked users cannot access protected actions

### Donation Requests

* Create donation request
* Get own donation requests
* Get public pending donation requests
* Get all donation requests for admin/volunteer
* View donation request details
* Edit donation request
* Cancel request
* Update request status
* Confirm donation

### User Management

* Admin can view all users
* Admin can block/unblock users
* Admin can change user role
* Default user role is donor
* Default user status is active

### Funding

* Create Stripe checkout session
* Verify Stripe payment success
* Save funding record in database
* Get user funding history
* Admin can view all funding records

## User Roles

### Donor

* Can create donation requests
* Can manage own requests
* Can give funding

### Volunteer

* Can view and update public donation requests

### Admin

* Can manage users
* Can manage roles and status
* Can view platform stats
* Can view all funding records
* Can manage donation requests

## NPM Packages Used

Main packages used in this backend:

* express
* cors
* dotenv
* mongodb
* cookie-parser
* jsonwebtoken
* stripe
* nodemon

## Environment Variables

The backend uses these environment variables:

```env
PORT=5000
MONGO_DB_URI=
AUTH_DB_NAME=lifedrop_db
JWT_ACCESS_SECRET=
STRIPE_SECRET_KEY=
CLIENT_URL=http://localhost:3000
PRODUCTION_CLIENT_URL=https://lifedrop-client.vercel.app
```

## Important Production Setup

For production, these values must be added in the backend Vercel environment variables:

```env
MONGO_DB_URI=
AUTH_DB_NAME=lifedrop_db
JWT_ACCESS_SECRET=
STRIPE_SECRET_KEY=
CLIENT_URL=https://lifedrop-client.vercel.app
PRODUCTION_CLIENT_URL=https://lifedrop-client.vercel.app
```

MongoDB Atlas Network Access should allow Vercel server access. For this project, I used MongoDB Atlas with production backend deployment.

## Run Locally

Install dependencies:

```bash
npm install
```

Run the backend locally:

```bash
npm run dev
```

Or:

```bash
node index.js
```

Local server:

```txt
http://localhost:5000
```

## Useful API Checks

Root route:

```txt
GET /
```

Health check:

```txt
GET /api/health
```

Public donors:

```txt
GET /api/donors
```

Public donation requests:

```txt
GET /api/donationRequests
```

JWT token route:

```txt
POST /api/jwt
```

## JWT Protection

Private APIs are protected using JWT token verification.

The frontend sends token like this:

```txt
Authorization: Bearer <token>
```

If token is missing or invalid, the backend returns unauthorized response. Admin and volunteer routes are also protected by role-based middleware.

## Deployment

The backend is deployed on Vercel from GitHub.

Live backend URL:

```txt
https://lifedrop-server-two.vercel.app
```

## Notes

The backend is prepared for production with CORS setup, 404 JSON response, global error handling, health check route, JWT protected private APIs, and Stripe sandbox payment integration.
