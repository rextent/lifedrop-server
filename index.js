const express = require("express");
const cors = require("cors");
const dns = require("node:dns");
require("dotenv").config();

const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// DNS fix for MongoDB
dns.setDefaultResultOrder("ipv4first");
dns.setServers(["8.8.8.8", "1.1.1.1"]);

const allowedOrigins = [
    "http://localhost:3000",
    "https://lifedrop-client.vercel.app",
    process.env.CLIENT_URL,
    process.env.PRODUCTION_CLIENT_URL,
].filter(Boolean);

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

const uri = process.env.MONGO_DB_URI;

if (!uri) {
    throw new Error("MONGO_DB_URI is missing in backend .env");
}

const jwtSecret = process.env.JWT_ACCESS_SECRET;

if (!jwtSecret) {
    throw new Error("JWT_ACCESS_SECRET is missing in backend .env");
}

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

let donationRequestCollection;
let userCollection;

const allowedBloodGroups = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"];

function validateDonationRequest(body) {
    if (!body.requesterName) return "Requester name is required.";
    if (!body.requesterEmail) return "Requester email is required.";
    if (!body.recipientName) return "Recipient name is required.";
    if (!body.recipientDistrict) return "Recipient district is required.";
    if (!body.recipientUpazila) return "Recipient upazila is required.";
    if (!body.hospitalName) return "Hospital name is required.";
    if (!body.fullAddressLine) return "Full address line is required.";
    if (!allowedBloodGroups.includes(body.bloodGroup)) {
        return "Valid blood group is required.";
    }
    if (!body.donationDate) return "Donation date is required.";
    if (!body.donationTime) return "Donation time is required.";
    if (!body.requestMessage) return "Request message is required.";

    return null;
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function run() {
    try {
        await client.connect();

        const database = client.db("lifedrop_db");

        const donationRequestCollection = database.collection("donationRequests");
        const userCollection = database.collection("user");
        const sessionCollection = database.collection("session");
        const fundingCollection = database.collection("fundings");

        const verifyJWT = async (req, res, next) => {
            try {
                const authHeader = req.headers.authorization;

                if (!authHeader || !authHeader.startsWith("Bearer ")) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: JWT token missing.",
                    });
                }

                const token = authHeader.split(" ")[1];

                const decoded = jwt.verify(token, jwtSecret);

                if (!decoded?.email) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: Invalid JWT payload.",
                    });
                }

                const user = await userCollection.findOne({
                    email: decoded.email,
                });

                if (!user) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: User not found.",
                    });
                }

                if (user.status === "blocked") {
                    return res.status(403).json({
                        success: false,
                        message: "Forbidden: Your account is blocked.",
                    });
                }

                req.user = {
                    ...user,
                    _id: user._id.toString(),
                    role: user.role || "donor",
                    status: user.status || "active",
                };

                next();
            } catch (error) {
                console.error("VERIFY_JWT_ERROR:", error);

                return res.status(401).json({
                    success: false,
                    message: "Unauthorized: Invalid or expired JWT token.",
                });
            }
        };

        const verifyAdminJWT = (req, res, next) => {
            if (req.user?.role !== "admin") {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden: Admin only.",
                });
            }

            next();
        };

        const verifyVolunteerOrAdminJWT = (req, res, next) => {
            if (req.user?.role !== "admin" && req.user?.role !== "volunteer") {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden: Volunteer or Admin only.",
                });
            }

            next();
        };

        const getSessionTokenFromCookies = (req) => {
            const cookies = req.cookies || {};
            const cookieKeys = Object.keys(cookies);

            const sessionCookieKey = cookieKeys.find(
                (key) =>
                    key.includes("better-auth") &&
                    key.includes("session")
            );

            if (!sessionCookieKey) {
                return null;
            }

            const rawToken = cookies[sessionCookieKey];

            if (!rawToken) {
                return null;
            }

            return decodeURIComponent(rawToken);
        };

        const verifyUser = async (req, res, next) => {
            try {
                const sessionToken = getSessionTokenFromCookies(req);

                if (!sessionToken) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: No session token found.",
                    });
                }

                const possibleTokens = [sessionToken];

                if (sessionToken.includes(".")) {
                    possibleTokens.push(sessionToken.split(".")[0]);
                }

                const session = await sessionCollection.findOne({
                    token: {
                        $in: possibleTokens,
                    },
                });

                if (!session) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: Invalid session.",
                    });
                }

                if (session.expiresAt && new Date(session.expiresAt) < new Date()) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: Session expired.",
                    });
                }

                const userQuery = [];

                if (session.userId) {
                    userQuery.push({ id: session.userId });

                    if (ObjectId.isValid(session.userId)) {
                        userQuery.push({ _id: new ObjectId(session.userId) });
                    }
                }

                if (userQuery.length === 0) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: User id not found in session.",
                    });
                }

                const user = await userCollection.findOne({
                    $or: userQuery,
                });

                if (!user) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: User not found.",
                    });
                }

                if (user.status === "blocked") {
                    return res.status(403).json({
                        success: false,
                        message: "Forbidden: Your account is blocked.",
                    });
                }

                req.user = user;
                next();
            } catch (error) {
                console.error("VERIFY_USER_ERROR:", error);

                return res.status(500).json({
                    success: false,
                    message: "Failed to verify user.",
                });
            }
        };

        const verifyAdmin = async (req, res, next) => {
            if (req.user?.role !== "admin") {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden: Admin only.",
                });
            }

            next();
        };

        const verifyVolunteerOrAdmin = async (req, res, next) => {
            if (req.user?.role !== "admin" && req.user?.role !== "volunteer") {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden: Volunteer or Admin only.",
                });
            }

            next();
        };

        app.get("/", (req, res) => {
            res.status(200).json({
                success: true,
                message: "LifeDrop server is running.",
            });
        });

        app.get("/api/health", async (req, res) => {
            try {
                await client.db("admin").command({ ping: 1 });

                res.status(200).json({
                    success: true,
                    message: "LifeDrop backend is healthy.",
                    server: "running",
                    database: "connected",
                    timestamp: new Date().toISOString(),
                });
            } catch (error) {
                console.error("HEALTH_CHECK_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Server is running, but database connection failed.",
                    server: "running",
                    database: "disconnected",
                    error: error.message,
                });
            }
        });

        app.get("/api/public/stats", async (req, res) => {
            try {
                const userCollection = database.collection("user");
                const donationRequestsCollection = database.collection("donationRequests");
                const fundingCollection = database.collection("fundings");

                const totalDonors = await userCollection.countDocuments({
                    role: "donor",
                    status: { $ne: "blocked" },
                });

                const totalRequests = await donationRequestsCollection.countDocuments();

                const successfulDonations = await donationRequestsCollection.countDocuments({
                    $or: [
                        { donationStatus: "done" },
                        { status: "done" },
                    ],
                });

                const paidFundings = await fundingCollection
                    .find({
                        paymentStatus: "paid",
                    })
                    .project({
                        amount: 1,
                    })
                    .toArray();

                const totalFundsRaised = paidFundings.reduce((total, funding) => {
                    return total + Number(funding.amount || 0);
                }, 0);

                res.status(200).json({
                    success: true,
                    stats: {
                        totalDonors,
                        totalRequests,
                        successfulDonations,
                        totalFundsRaised,
                    },
                });
            } catch (error) {
                console.error("PUBLIC_STATS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load public stats.",
                    error: error.message,
                });
            }
        });

        app.get("/api/auth/me", verifyJWT, async (req, res) => {
            res.status(200).json({
                success: true,
                user: {
                    _id: req.user._id?.toString(),
                    id: req.user.id,
                    name: req.user.name,
                    email: req.user.email,
                    image: req.user.image,
                    role: req.user.role,
                    status: req.user.status,
                    bloodGroup: req.user.bloodGroup,
                    district: req.user.district,
                    upazila: req.user.upazila,
                },
            });
        });

        app.get("/api/admin/stats", verifyJWT, verifyAdminJWT, async (req, res) => {
            try {
                const totalDonationRequests =
                    await donationRequestCollection.countDocuments();

                const totalDonors = await userCollection.countDocuments({
                    role: "donor",
                });

                const totalVolunteers = await userCollection.countDocuments({
                    role: "volunteer",
                });

                // Funding bonus section later হবে, তাই আপাতত 0
                const totalFunding = 0;

                res.status(200).json({
                    success: true,
                    stats: {
                        totalDonationRequests,
                        totalDonors,
                        totalVolunteers,
                        totalFunding,
                    },
                });
            } catch (error) {
                console.error("GET_ADMIN_STATS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load admin statistics.",
                });
            }
        });

        // Get dashboard stats based on user role
        app.get("/api/dashboard/stats", verifyJWT, async (req, res) => {
            try {
                const role = req.user?.role || "donor";
                const email = req.user?.email;

                // Admin and Volunteer will see the same platform dashboard overview
                if (role === "admin" || role === "volunteer") {
                    const totalDonationRequests =
                        await donationRequestCollection.countDocuments();

                    const totalDonors = await userCollection.countDocuments({
                        role: "donor",
                    });

                    const totalVolunteers = await userCollection.countDocuments({
                        role: "volunteer",
                    });

                    const totalFundingResult = await fundingCollection
                        .aggregate([
                            {
                                $match: {
                                    paymentStatus: "paid",
                                },
                            },
                            {
                                $group: {
                                    _id: null,
                                    total: {
                                        $sum: "$amount",
                                    },
                                },
                            },
                        ])
                        .toArray();

                    const totalFunding = totalFundingResult[0]?.total || 0;

                    const recentDonationRequests = await donationRequestCollection
                        .find({})
                        .sort({ createdAt: -1, _id: -1 })
                        .limit(3)
                        .project({
                            requesterName: 1,
                            requesterEmail: 1,
                            recipientName: 1,
                            recipientDistrict: 1,
                            recipientUpazila: 1,
                            bloodGroup: 1,
                            donationDate: 1,
                            donationTime: 1,
                            donationStatus: 1,
                            createdAt: 1,
                        })
                        .toArray();

                    const recentFundings = await fundingCollection
                        .find({
                            paymentStatus: "paid",
                        })
                        .sort({ createdAt: -1, _id: -1 })
                        .limit(3)
                        .project({
                            userName: 1,
                            userEmail: 1,
                            amount: 1,
                            paymentStatus: 1,
                            transactionId: 1,
                            createdAt: 1,
                        })
                        .toArray();

                    return res.status(200).json({
                        success: true,
                        role,
                        dashboardType: "platform",
                        stats: {
                            totalDonationRequests,
                            totalDonors,
                            totalVolunteers,
                            totalFunding,
                        },
                        recentDonationRequests: recentDonationRequests.map((request) => ({
                            ...request,
                            _id: request._id.toString(),
                        })),
                        recentFundings: recentFundings.map((funding) => ({
                            ...funding,
                            _id: funding._id.toString(),
                        })),
                    });
                }

                // Donor dashboard overview
                const myTotalRequests =
                    await donationRequestCollection.countDocuments({
                        requesterEmail: email,
                    });

                const myPendingRequests =
                    await donationRequestCollection.countDocuments({
                        requesterEmail: email,
                        donationStatus: "pending",
                    });

                const myInProgressRequests =
                    await donationRequestCollection.countDocuments({
                        requesterEmail: email,
                        donationStatus: "inprogress",
                    });

                const myCompletedRequests =
                    await donationRequestCollection.countDocuments({
                        requesterEmail: email,
                        donationStatus: "done",
                    });

                return res.status(200).json({
                    success: true,
                    role: "donor",
                    dashboardType: "donor",
                    stats: {
                        myTotalRequests,
                        myPendingRequests,
                        myInProgressRequests,
                        myCompletedRequests,
                    },
                });
            } catch (error) {
                console.error("GET_DASHBOARD_STATS_ERROR:", error);

                return res.status(500).json({
                    success: false,
                    message: "Failed to load dashboard statistics.",
                });
            }
        });

        // Get all users for admin dashboard with status filter + pagination
        app.get("/api/admin/users", verifyJWT, verifyAdminJWT, async (req, res) => {
            try {
                const {
                    status = "all",
                    page = 1,
                    limit = 10,
                } = req.query;

                const query = {};

                if (status === "active") {
                    query.$or = [
                        { status: "active" },
                        { status: { $exists: false } },
                        { status: null },
                        { status: "" },
                    ];
                }

                if (status === "blocked") {
                    query.status = "blocked";
                }

                const currentPage = Math.max(Number(page) || 1, 1);
                const perPage = Math.max(Number(limit) || 10, 1);
                const skip = (currentPage - 1) * perPage;

                const total = await userCollection.countDocuments(query);

                const users = await userCollection
                    .find(query)
                    .sort({ createdAt: -1, _id: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .project({
                        name: 1,
                        email: 1,
                        image: 1,
                        avatar: 1,
                        avatarUrl: 1,
                        role: 1,
                        status: 1,
                        bloodGroup: 1,
                        district: 1,
                        upazila: 1,
                        createdAt: 1,
                    })
                    .toArray();

                const formattedUsers = users.map((user) => ({
                    ...user,
                    _id: user._id.toString(),
                    role: user.role || "donor",
                    status: user.status || "active",
                }));

                res.status(200).json({
                    success: true,
                    users: formattedUsers,
                    pagination: {
                        page: currentPage,
                        limit: perPage,
                        total,
                        totalPages: Math.ceil(total / perPage),
                    },
                });
            } catch (error) {
                console.error("GET_ADMIN_USERS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load users.",
                });
            }
        });

        // Create JWT token after successful login/signup
        app.post("/api/jwt", async (req, res) => {
            try {
                const { email } = req.body;

                if (!email) {
                    return res.status(400).json({
                        success: false,
                        message: "Email is required.",
                    });
                }

                const user = await userCollection.findOne({
                    email,
                });

                if (!user) {
                    return res.status(404).json({
                        success: false,
                        message: "User not found.",
                    });
                }

                if (user.status === "blocked") {
                    return res.status(403).json({
                        success: false,
                        message: "Blocked user cannot get access token.",
                    });
                }

                const tokenPayload = {
                    id: user._id.toString(),
                    email: user.email,
                    name: user.name || "",
                    role: user.role || "donor",
                    status: user.status || "active",
                };

                const token = jwt.sign(tokenPayload, jwtSecret, {
                    expiresIn: "7d",
                });

                res.status(200).json({
                    success: true,
                    token,
                    user: tokenPayload,
                });
            } catch (error) {
                console.error("CREATE_JWT_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to create JWT token.",
                });
            }
        });

        // Block or unblock user
        app.patch("/api/admin/users/:id/status", verifyJWT, verifyAdminJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { status } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid user id.",
                    });
                }

                if (!["active", "blocked"].includes(status)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid user status.",
                    });
                }

                if (req.user?._id?.toString() === id) {
                    return res.status(400).json({
                        success: false,
                        message: "You cannot change your own status.",
                    });
                }

                const result = await userCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            status,
                            updatedAt: new Date(),
                        },
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "User not found.",
                    });
                }

                const updatedUser = await userCollection.findOne(
                    { _id: new ObjectId(id) },
                    {
                        projection: {
                            name: 1,
                            email: 1,
                            image: 1,
                            avatar: 1,
                            avatarUrl: 1,
                            role: 1,
                            status: 1,
                            bloodGroup: 1,
                            district: 1,
                            upazila: 1,
                            createdAt: 1,
                        },
                    }
                );

                res.status(200).json({
                    success: true,
                    message:
                        status === "blocked"
                            ? "User blocked successfully."
                            : "User unblocked successfully.",
                    user: {
                        ...updatedUser,
                        _id: updatedUser._id.toString(),
                        role: updatedUser.role || "donor",
                        status: updatedUser.status || "active",
                    },
                });
            } catch (error) {
                console.error("UPDATE_USER_STATUS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to update user status.",
                });
            }
        });

        // Make volunteer or make admin
        app.patch("/api/admin/users/:id/role", verifyJWT, verifyAdminJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { role } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid user id.",
                    });
                }

                if (!["donor", "volunteer", "admin"].includes(role)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid user role.",
                    });
                }

                if (req.user?._id?.toString() === id) {
                    return res.status(400).json({
                        success: false,
                        message: "You cannot change your own role.",
                    });
                }

                const result = await userCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            role,
                            updatedAt: new Date(),
                        },
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "User not found.",
                    });
                }

                const updatedUser = await userCollection.findOne(
                    { _id: new ObjectId(id) },
                    {
                        projection: {
                            name: 1,
                            email: 1,
                            image: 1,
                            avatar: 1,
                            avatarUrl: 1,
                            role: 1,
                            status: 1,
                            bloodGroup: 1,
                            district: 1,
                            upazila: 1,
                            createdAt: 1,
                        },
                    }
                );

                res.status(200).json({
                    success: true,
                    message:
                        role === "admin"
                            ? "User role updated to admin successfully."
                            : role === "volunteer"
                                ? "User role updated to volunteer successfully."
                                : "User role updated successfully.",
                    user: {
                        ...updatedUser,
                        _id: updatedUser._id.toString(),
                        role: updatedUser.role || "donor",
                        status: updatedUser.status || "active",
                    },
                });
            } catch (error) {
                console.error("UPDATE_USER_ROLE_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to update user role.",
                });
            }
        });

        // Get all funding records for admin with pagination, search and filter
        app.get("/api/admin/fundings", verifyJWT, verifyAdminJWT, async (req, res) => {
            try {
                const {
                    page = 1,
                    limit = 10,
                    status = "all",
                    search = "",
                    startDate = "",
                    endDate = "",
                } = req.query;

                const query = {};

                if (status !== "all") {
                    query.paymentStatus = status;
                }

                if (search.trim()) {
                    const safeSearch = search
                        .trim()
                        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

                    const searchRegex = new RegExp(safeSearch, "i");

                    query.$or = [
                        { userName: searchRegex },
                        { userEmail: searchRegex },
                        { transactionId: searchRegex },
                    ];
                }

                if (startDate || endDate) {
                    query.createdAt = {};

                    if (startDate) {
                        query.createdAt.$gte = new Date(startDate);
                    }

                    if (endDate) {
                        const end = new Date(endDate);
                        end.setHours(23, 59, 59, 999);
                        query.createdAt.$lte = end;
                    }
                }

                const currentPage = Math.max(Number(page) || 1, 1);
                const perPage = Math.max(Number(limit) || 10, 1);
                const skip = (currentPage - 1) * perPage;

                const total = await fundingCollection.countDocuments(query);

                const fundings = await fundingCollection
                    .find(query)
                    .sort({ createdAt: -1, _id: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .project({
                        userName: 1,
                        userEmail: 1,
                        amount: 1,
                        paymentStatus: 1,
                        transactionId: 1,
                        createdAt: 1,
                    })
                    .toArray();

                const totalFundingResult = await fundingCollection
                    .aggregate([
                        {
                            $match: {
                                paymentStatus: "paid",
                            },
                        },
                        {
                            $group: {
                                _id: null,
                                total: {
                                    $sum: "$amount",
                                },
                            },
                        },
                    ])
                    .toArray();

                const filteredFundingResult = await fundingCollection
                    .aggregate([
                        {
                            $match: {
                                ...query,
                                paymentStatus: "paid",
                            },
                        },
                        {
                            $group: {
                                _id: null,
                                total: {
                                    $sum: "$amount",
                                },
                            },
                        },
                    ])
                    .toArray();

                res.status(200).json({
                    success: true,
                    fundings: fundings.map((funding) => ({
                        ...funding,
                        _id: funding._id.toString(),
                    })),
                    summary: {
                        totalFunding: totalFundingResult[0]?.total || 0,
                        filteredFunding: filteredFundingResult[0]?.total || 0,
                    },
                    pagination: {
                        page: currentPage,
                        limit: perPage,
                        total,
                        totalPages: Math.ceil(total / perPage),
                    },
                });
            } catch (error) {
                console.error("GET_ADMIN_FUNDINGS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load admin fundings.",
                });
            }
        });

        // Get all donation requests for admin/volunteer dashboard with filter + pagination
        app.get("/api/dashboard/donation-requests", verifyJWT, verifyVolunteerOrAdminJWT, async (req, res) => {
            try {
                const {
                    status = "all",
                    page = 1,
                    limit = 10,
                } = req.query;

                const allowedStatuses = ["pending", "inprogress", "done", "canceled"];

                const query = {};

                if (status !== "all" && allowedStatuses.includes(status)) {
                    query.donationStatus = status;
                }

                const currentPage = Math.max(Number(page) || 1, 1);
                const perPage = Math.max(Number(limit) || 10, 1);
                const skip = (currentPage - 1) * perPage;

                const total = await donationRequestCollection.countDocuments(query);

                const requests = await donationRequestCollection
                    .find(query)
                    .sort({ createdAt: -1, _id: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .toArray();

                const formattedRequests = requests.map((request) => ({
                    ...request,
                    _id: request._id.toString(),
                }));

                res.status(200).json({
                    success: true,
                    role: req.user.role,
                    requests: formattedRequests,
                    pagination: {
                        page: currentPage,
                        limit: perPage,
                        total,
                        totalPages: Math.ceil(total / perPage),
                    },
                });
            } catch (error) {
                console.error("GET_DASHBOARD_DONATION_REQUESTS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load donation requests.",
                });
            }
        });

        // Update donation request status by admin/volunteer
        app.patch("/api/dashboard/donation-requests/:id/status", verifyJWT, verifyVolunteerOrAdminJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { status } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                const allowedStatuses = ["pending", "inprogress", "done", "canceled"];

                if (!allowedStatuses.includes(status)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation status.",
                    });
                }

                const result = await donationRequestCollection.updateOne(
                    {
                        _id: new ObjectId(id),
                    },
                    {
                        $set: {
                            donationStatus: status,
                            updatedAt: new Date(),
                        },
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Donation request not found.",
                    });
                }

                const updatedRequest = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                });

                res.status(200).json({
                    success: true,
                    message: "Donation request status updated successfully.",
                    request: {
                        ...updatedRequest,
                        _id: updatedRequest._id.toString(),
                    },
                });
            } catch (error) {
                console.error("UPDATE_DASHBOARD_DONATION_STATUS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to update donation request status.",
                });
            }
        });

        // Fix missing role/status for existing users
        // app.patch("/api/admin/users/fix-defaults", verifyUser, verifyAdmin, async (req, res) => {
        //     try {
        //         const statusResult = await userCollection.updateMany(
        //             {
        //                 $or: [
        //                     { status: { $exists: false } },
        //                     { status: null },
        //                     { status: "" },
        //                 ],
        //             },
        //             {
        //                 $set: {
        //                     status: "active",
        //                     updatedAt: new Date(),
        //                 },
        //             }
        //         );

        //         const roleResult = await userCollection.updateMany(
        //             {
        //                 $or: [
        //                     { role: { $exists: false } },
        //                     { role: null },
        //                     { role: "" },
        //                 ],
        //             },
        //             {
        //                 $set: {
        //                     role: "donor",
        //                     updatedAt: new Date(),
        //                 },
        //             }
        //         );

        //         res.status(200).json({
        //             success: true,
        //             message: "Missing user defaults fixed successfully.",
        //             updated: {
        //                 statusModified: statusResult.modifiedCount,
        //                 roleModified: roleResult.modifiedCount,
        //             },
        //         });
        //     } catch (error) {
        //         console.error("FIX_USER_DEFAULTS_ERROR:", error);

        //         res.status(500).json({
        //             success: false,
        //             message: "Failed to fix user defaults.",
        //         });
        //     }
        // });

        // Ensure default role/status after user registration
        app.patch("/api/users/defaults", async (req, res) => {
            try {
                const { email } = req.body;

                if (!email) {
                    return res.status(400).json({
                        success: false,
                        message: "User email is required.",
                    });
                }

                const user = await userCollection.findOne({ email });

                if (!user) {
                    return res.status(404).json({
                        success: false,
                        message: "User not found.",
                    });
                }

                const updateDoc = {};

                if (!user.role) {
                    updateDoc.role = "donor";
                }

                if (!user.status) {
                    updateDoc.status = "active";
                }

                if (Object.keys(updateDoc).length === 0) {
                    return res.status(200).json({
                        success: true,
                        message: "User defaults already exist.",
                    });
                }

                updateDoc.updatedAt = new Date();

                await userCollection.updateOne(
                    { email },
                    {
                        $set: updateDoc,
                    }
                );

                res.status(200).json({
                    success: true,
                    message: "User defaults updated successfully.",
                });
            } catch (error) {
                console.error("ENSURE_USER_DEFAULTS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to ensure user defaults.",
                });
            }
        });

        app.post("/api/donationRequests", verifyJWT, async (req, res) => {
            try {
                const donationRequest = req.body;

                const validationError = validateDonationRequest(donationRequest);

                if (validationError) {
                    return res.status(400).json({
                        success: false,
                        message: validationError,
                    });
                }

                const requester = await userCollection.findOne({
                    email: donationRequest.requesterEmail,
                });

                if (!requester) {
                    return res.status(404).json({
                        success: false,
                        message: "Requester user not found.",
                    });
                }

                if (requester.status === "blocked") {
                    return res.status(403).json({
                        success: false,
                        message: "Blocked users cannot create donation requests.",
                    });
                }

                const newDonationRequest = {
                    requesterId: requester.id || donationRequest.requesterId || "",
                    requesterName: donationRequest.requesterName,
                    requesterEmail: donationRequest.requesterEmail,

                    recipientName: donationRequest.recipientName,
                    recipientDistrict: donationRequest.recipientDistrict,
                    recipientUpazila: donationRequest.recipientUpazila,

                    hospitalName: donationRequest.hospitalName,
                    fullAddressLine: donationRequest.fullAddressLine,

                    bloodGroup: donationRequest.bloodGroup,
                    donationDate: donationRequest.donationDate,
                    donationTime: donationRequest.donationTime,
                    requestMessage: donationRequest.requestMessage,

                    donationStatus: "pending",

                    donorName: "",
                    donorEmail: "",

                    createdAt: new Date(),
                    updatedAt: new Date(),
                };

                const result = await donationRequestCollection.insertOne(
                    newDonationRequest
                );

                res.status(201).json({
                    success: true,
                    message: "Donation request created successfully.",
                    insertedId: result.insertedId,
                    request: {
                        _id: result.insertedId,
                        ...newDonationRequest,
                    },
                });
            } catch (error) {
                console.error("CREATE_DONATION_REQUEST_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to create donation request.",
                });
            }
        });
        // Get logged-in user's donation requests with filter + pagination
        app.get("/api/donationRequests/my", verifyJWT, async (req, res) => {
            try {
                const { email, status = "all", page = 1, limit = 10 } = req.query;

                if (!email) {
                    return res.status(400).json({
                        success: false,
                        message: "Requester email is required.",
                    });
                }

                const query = {
                    requesterEmail: email,
                };

                const allowedStatuses = ["pending", "inprogress", "done", "canceled"];

                if (status !== "all" && allowedStatuses.includes(status)) {
                    query.donationStatus = status;
                }

                const currentPage = Number(page) || 1;
                const perPage = Number(limit) || 10;
                const skip = (currentPage - 1) * perPage;

                const total = await donationRequestCollection.countDocuments(query);

                const requests = await donationRequestCollection
                    .find(query)
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .toArray();

                const formattedRequests = requests.map((request) => ({
                    ...request,
                    _id: request._id.toString(),
                }));

                res.json({
                    success: true,
                    requests: formattedRequests,
                    pagination: {
                        page: currentPage,
                        limit: perPage,
                        total,
                        totalPages: Math.ceil(total / perPage),
                    },
                });
            } catch (error) {
                console.error("GET_MY_DONATION_REQUESTS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load donation requests.",
                });
            }
        });

        // Get all donors for public search donors page with filter + pagination
        app.get("/api/donors", async (req, res) => {
            try {
                const {
                    bloodGroup = "all",
                    district = "",
                    upazila = "",
                    page = 1,
                    limit = 8,
                } = req.query;

                const query = {
                    role: "donor",
                };

                if (bloodGroup !== "all") {
                    query.bloodGroup = bloodGroup;
                }

                if (district.trim()) {
                    query.district = {
                        $regex: escapeRegex(district.trim()),
                        $options: "i",
                    };
                }

                if (upazila.trim()) {
                    query.upazila = {
                        $regex: escapeRegex(upazila.trim()),
                        $options: "i",
                    };
                }

                const currentPage = Number(page) || 1;
                const perPage = Number(limit) || 8;
                const skip = (currentPage - 1) * perPage;

                const total = await userCollection.countDocuments(query);

                const donors = await userCollection
                    .find(query)
                    .sort({ createdAt: -1, _id: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .project({
                        name: 1,
                        email: 1,
                        image: 1,
                        avatar: 1,
                        avatarUrl: 1,
                        bloodGroup: 1,
                        district: 1,
                        upazila: 1,
                        role: 1,
                        status: 1,
                        createdAt: 1,
                    })
                    .toArray();

                const formattedDonors = donors.map((donor) => ({
                    ...donor,
                    _id: donor._id.toString(),
                }));

                return res.status(200).json({
                    success: true,
                    donors: formattedDonors,
                    pagination: {
                        page: currentPage,
                        limit: perPage,
                        total,
                        totalPages: Math.ceil(total / perPage),
                    },
                });
            } catch (error) {
                console.error("GET_PUBLIC_DONORS_ERROR:", error);

                return res.status(500).json({
                    success: false,
                    message: error.message || "Failed to load donors.",
                });
            }
        });

        // Get all pending donation requests for public page with filter + pagination
        app.get("/api/donationRequests", async (req, res) => {
            try {
                const {
                    status = "pending",
                    bloodGroup = "all",
                    district = "",
                    upazila = "",
                    page = 1,
                    limit = 6,
                } = req.query;

                if (status !== "pending") {
                    return res.status(400).json({
                        success: false,
                        message: "Only pending donation requests are public.",
                    });
                }

                const query = {
                    donationStatus: "pending",
                };

                if (bloodGroup !== "all") {
                    query.bloodGroup = bloodGroup;
                }

                if (district.trim()) {
                    query.recipientDistrict = {
                        $regex: escapeRegex(district.trim()),
                        $options: "i",
                    };
                }

                if (upazila.trim()) {
                    query.recipientUpazila = {
                        $regex: escapeRegex(upazila.trim()),
                        $options: "i",
                    };
                }

                const currentPage = Number(page) || 1;
                const perPage = Number(limit) || 6;
                const skip = (currentPage - 1) * perPage;

                const total = await donationRequestCollection.countDocuments(query);

                const requests = await donationRequestCollection
                    .find(query)
                    .sort({ createdAt: -1, _id: -1 })
                    .skip(skip)
                    .limit(perPage)
                    .project({
                        requesterName: 0,
                        requesterEmail: 0,
                        donorName: 0,
                        donorEmail: 0,
                    })
                    .toArray();

                const formattedRequests = requests.map((request) => ({
                    ...request,
                    _id: request._id.toString(),
                }));

                return res.status(200).json({
                    success: true,
                    count: formattedRequests.length,
                    requests: formattedRequests,
                    pagination: {
                        page: currentPage,
                        limit: perPage,
                        total,
                        totalPages: Math.ceil(total / perPage),
                    },
                });
            } catch (error) {
                console.error("GET_PUBLIC_DONATION_REQUESTS_ERROR:", error);

                return res.status(500).json({
                    success: false,
                    message: error.message || "Failed to load pending donation requests.",
                });
            }
        });

        // Get single donation request details for private details page
        app.get("/api/donationRequests/details/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                const request = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                });

                if (!request) {
                    return res.status(404).json({
                        success: false,
                        message: "Donation request not found.",
                    });
                }

                return res.status(200).json({
                    success: true,
                    request: {
                        ...request,
                        _id: request._id.toString(),
                    },
                });
            } catch (error) {
                console.error("GET_DONATION_REQUEST_DETAILS_ERROR:", error);

                return res.status(500).json({
                    success: false,
                    message: "Failed to load donation request details.",
                });
            }
        });



        // Get logged-in user's funding records
        app.get("/api/fundings", verifyJWT, async (req, res) => {
            try {
                const userEmail = req.user?.email;

                if (!userEmail) {
                    return res.status(401).json({
                        success: false,
                        message: "Unauthorized: User email not found.",
                    });
                }

                const query = {
                    userEmail,
                };

                const fundings = await fundingCollection
                    .find(query)
                    .sort({ createdAt: -1, _id: -1 })
                    .project({
                        userName: 1,
                        userEmail: 1,
                        amount: 1,
                        paymentStatus: 1,
                        transactionId: 1,
                        createdAt: 1,
                    })
                    .toArray();

                const formattedFundings = fundings.map((funding) => ({
                    ...funding,
                    _id: funding._id.toString(),
                }));

                const totalFundingResult = await fundingCollection
                    .aggregate([
                        {
                            $match: {
                                userEmail,
                                paymentStatus: "paid",
                            },
                        },
                        {
                            $group: {
                                _id: null,
                                total: {
                                    $sum: "$amount",
                                },
                            },
                        },
                    ])
                    .toArray();

                const totalFunding = totalFundingResult[0]?.total || 0;

                res.status(200).json({
                    success: true,
                    fundings: formattedFundings,
                    totalFunding,
                });
            } catch (error) {
                console.error("GET_USER_FUNDINGS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load your fundings.",
                });
            }
        });

        // Create Stripe checkout session for funding
        app.post("/api/create-checkout-session", verifyJWT, async (req, res) => {
            try {
                const { amount } = req.body;

                const fundingAmount = Number(amount);

                if (!fundingAmount || fundingAmount < 1) {
                    return res.status(400).json({
                        success: false,
                        message: "Minimum funding amount is $1.",
                    });
                }

                const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

                const session = await stripe.checkout.sessions.create({
                    payment_method_types: ["card"],
                    mode: "payment",
                    customer_email: req.user.email,
                    line_items: [
                        {
                            price_data: {
                                currency: "usd",
                                product_data: {
                                    name: "LifeDrop Organization Funding",
                                    description: "Donation fund for LifeDrop blood donation organization.",
                                },
                                unit_amount: fundingAmount * 100,
                            },
                            quantity: 1,
                        },
                    ],
                    metadata: {
                        userName: req.user.name || "Unknown User",
                        userEmail: req.user.email,
                        amount: String(fundingAmount),
                    },
                    success_url: `${clientUrl}/funding/success?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${clientUrl}/funding/cancel`,
                });

                res.status(200).json({
                    success: true,
                    url: session.url,
                });
            } catch (error) {
                console.error("CREATE_CHECKOUT_SESSION_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to create checkout session.",
                });
            }
        });

        // Verify Stripe session and save funding
        app.post("/api/payment/success", verifyJWT, async (req, res) => {
            try {
                const { sessionId } = req.body;

                if (!sessionId) {
                    return res.status(400).json({
                        success: false,
                        message: "Session id is required.",
                    });
                }

                const session = await stripe.checkout.sessions.retrieve(sessionId);

                if (!session) {
                    return res.status(404).json({
                        success: false,
                        message: "Stripe session not found.",
                    });
                }

                if (session.payment_status !== "paid") {
                    return res.status(400).json({
                        success: false,
                        message: "Payment is not completed.",
                    });
                }

                const existingFunding = await fundingCollection.findOne({
                    transactionId: session.id,
                });

                if (existingFunding) {
                    return res.status(200).json({
                        success: true,
                        message: "Funding already recorded.",
                        funding: {
                            ...existingFunding,
                            _id: existingFunding._id.toString(),
                        },
                    });
                }

                const amount = Number(session.metadata?.amount) || session.amount_total / 100;

                const fundingDoc = {
                    userName: session.metadata?.userName || req.user.name || "Unknown User",
                    userEmail: session.metadata?.userEmail || req.user.email,
                    amount,
                    transactionId: session.id,
                    paymentStatus: session.payment_status,
                    createdAt: new Date(),
                };

                const result = await fundingCollection.insertOne(fundingDoc);

                res.status(201).json({
                    success: true,
                    message: "Funding recorded successfully.",
                    funding: {
                        _id: result.insertedId.toString(),
                        ...fundingDoc,
                    },
                });
            } catch (error) {
                console.error("PAYMENT_SUCCESS_VERIFY_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to verify payment.",
                });
            }
        });


        // Confirm donation and change status pending to inprogress
        app.patch("/api/donationRequests/:id/donate", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { donorName, donorEmail } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                if (!donorName) {
                    return res.status(400).json({
                        success: false,
                        message: "Donor name is required.",
                    });
                }

                if (!donorEmail) {
                    return res.status(400).json({
                        success: false,
                        message: "Donor email is required.",
                    });
                }

                const result = await donationRequestCollection.updateOne(
                    {
                        _id: new ObjectId(id),
                        donationStatus: "pending",
                    },
                    {
                        $set: {
                            donationStatus: "inprogress",
                            donorName,
                            donorEmail,
                            updatedAt: new Date(),
                        },
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(400).json({
                        success: false,
                        message: "This request is not available for donation.",
                    });
                }

                const updatedRequest = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                });

                return res.status(200).json({
                    success: true,
                    message: "Donation confirmed successfully.",
                    request: {
                        ...updatedRequest,
                        _id: updatedRequest._id.toString(),
                    },
                });
            } catch (error) {
                console.error("CONFIRM_DONATION_ERROR:", error);

                return res.status(500).json({
                    success: false,
                    message: "Failed to confirm donation.",
                });
            }
        });


        // Get single donation request by id for edit page
        app.get("/api/donationRequests/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { email } = req.query;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                const requestQuery = {
                    _id: new ObjectId(id),
                };

                // Admin can access any request
                if (req.user?.role !== "admin") {
                    if (!email) {
                        return res.status(400).json({
                            success: false,
                            message: "Requester email is required.",
                        });
                    }

                    if (req.user?.email !== email) {
                        return res.status(403).json({
                            success: false,
                            message: "Forbidden: You can only access your own request.",
                        });
                    }

                    requestQuery.requesterEmail = email;
                }

                const request = await donationRequestCollection.findOne(requestQuery);

                if (!request) {
                    return res.status(404).json({
                        success: false,
                        message: "Donation request not found.",
                    });
                }

                res.json({
                    success: true,
                    request: {
                        ...request,
                        _id: request._id.toString(),
                    },
                });
            } catch (error) {
                console.error("GET_SINGLE_DONATION_REQUEST_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to load donation request.",
                });
            }
        });

        // Update donation request
        app.put("/api/donationRequests/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const body = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                if (!body.recipientName) {
                    return res.status(400).json({
                        success: false,
                        message: "Recipient name is required.",
                    });
                }

                if (!body.recipientDistrict) {
                    return res.status(400).json({
                        success: false,
                        message: "Recipient district is required.",
                    });
                }

                if (!body.recipientUpazila) {
                    return res.status(400).json({
                        success: false,
                        message: "Recipient upazila is required.",
                    });
                }

                if (!body.hospitalName) {
                    return res.status(400).json({
                        success: false,
                        message: "Hospital name is required.",
                    });
                }

                if (!body.fullAddressLine) {
                    return res.status(400).json({
                        success: false,
                        message: "Full address line is required.",
                    });
                }

                if (!body.bloodGroup) {
                    return res.status(400).json({
                        success: false,
                        message: "Blood group is required.",
                    });
                }

                if (!body.donationDate) {
                    return res.status(400).json({
                        success: false,
                        message: "Donation date is required.",
                    });
                }

                if (!body.donationTime) {
                    return res.status(400).json({
                        success: false,
                        message: "Donation time is required.",
                    });
                }

                if (!body.requestMessage) {
                    return res.status(400).json({
                        success: false,
                        message: "Request message is required.",
                    });
                }

                const request = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                });

                if (!request) {
                    return res.status(404).json({
                        success: false,
                        message: "Donation request not found.",
                    });
                }

                // Donor can update only own request
                // Admin can update any request
                if (req.user?.role !== "admin") {
                    if (request.requesterEmail !== req.user?.email) {
                        return res.status(403).json({
                            success: false,
                            message: "Forbidden: You can only update your own request.",
                        });
                    }
                }

                const updateDoc = {
                    recipientName: body.recipientName,
                    recipientDistrict: body.recipientDistrict,
                    recipientUpazila: body.recipientUpazila,
                    hospitalName: body.hospitalName,
                    fullAddressLine: body.fullAddressLine,
                    bloodGroup: body.bloodGroup,
                    donationDate: body.donationDate,
                    donationTime: body.donationTime,
                    requestMessage: body.requestMessage,
                    updatedAt: new Date(),
                };

                const result = await donationRequestCollection.updateOne(
                    {
                        _id: new ObjectId(id),
                    },
                    {
                        $set: updateDoc,
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Donation request not found.",
                    });
                }

                const updatedRequest = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                });

                res.json({
                    success: true,
                    message: "Donation request updated successfully.",
                    request: {
                        ...updatedRequest,
                        _id: updatedRequest._id.toString(),
                    },
                });
            } catch (error) {
                console.error("UPDATE_DONATION_REQUEST_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to update donation request.",
                });
            }
        });

        // Update donation request status
        app.patch("/api/donationRequests/:id/status", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { status, requesterEmail } = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid request id.",
                    });
                }

                if (!requesterEmail) {
                    return res.status(400).json({
                        success: false,
                        message: "Requester email is required.",
                    });
                }

                const allowedStatuses = ["done", "canceled"];

                if (!allowedStatuses.includes(status)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid status update.",
                    });
                }

                let currentStatusFilter = {};

                if (status === "done") {
                    currentStatusFilter = { donationStatus: "inprogress" };
                }

                if (status === "canceled") {
                    currentStatusFilter = {
                        donationStatus: {
                            $in: ["pending", "inprogress"],
                        },
                    };
                }

                const result = await donationRequestCollection.updateOne(
                    {
                        _id: new ObjectId(id),
                        requesterEmail,
                        ...currentStatusFilter,
                    },
                    {
                        $set: {
                            donationStatus: status,
                            updatedAt: new Date(),
                        },
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Request not found or status cannot be changed.",
                    });
                }

                const updatedRequest = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                });

                res.json({
                    success: true,
                    message:
                        status === "canceled"
                            ? "Donation request canceled successfully."
                            : "Donation request marked as done.",
                    request: {
                        ...updatedRequest,
                        _id: updatedRequest._id.toString(),
                    },
                });
            } catch (error) {
                console.error("UPDATE_DONATION_STATUS_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to update donation request status.",
                });
            }
        });

        // Delete own donation request
        app.delete("/api/donationRequests/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                const { email } = req.query;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid request id.",
                    });
                }

                if (!email) {
                    return res.status(400).json({
                        success: false,
                        message: "Requester email is required.",
                    });
                }

                const result = await donationRequestCollection.deleteOne({
                    _id: new ObjectId(id),
                    requesterEmail: email,
                });

                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Donation request not found.",
                    });
                }

                res.json({
                    success: true,
                    message: "Donation request deleted successfully.",
                });
            } catch (error) {
                console.error("DELETE_DONATION_REQUEST_ERROR:", error);

                res.status(500).json({
                    success: false,
                    message: "Failed to delete donation request.",
                });
            }
        });

        app.use((req, res) => {
            res.status(404).json({
                success: false,
                message: `Route not found: ${req.method} ${req.originalUrl}`,
            });
        });

        app.use((error, req, res, next) => {
            console.error("GLOBAL_SERVER_ERROR:", error);

            const statusCode = error.status || error.statusCode || 500;

            res.status(statusCode).json({
                success: false,
                message: error.message || "Internal server error.",
            });
        });

        await client.db("admin").command({ ping: 1 });

        console.log("MongoDB connected successfully.");

        app.listen(port, () => {
            console.log(`LifeDrop backend running on port ${port}`);
        });
    } catch (error) {
        console.error("MongoDB connection failed:", error);
    }
}

run();