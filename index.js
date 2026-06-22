const express = require("express");
const cors = require("cors");
const dns = require("node:dns");
require("dotenv").config();

const cookieParser = require("cookie-parser");

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// DNS fix for MongoDB
dns.setDefaultResultOrder("ipv4first");
dns.setServers(["8.8.8.8", "1.1.1.1"]);

app.use(
    cors({
        origin: ["http://localhost:3000"],
        credentials: true,
    })
);

app.use(express.json());
app.use(cookieParser());

const uri = process.env.MONGO_DB_URI;

if (!uri) {
    throw new Error("MONGO_DB_URI is missing in backend .env");
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

        donationRequestCollection = database.collection("donationRequests");
        userCollection = database.collection("user");
        const sessionCollection = database.collection("session");

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
            res.send("LifeDrop backend is running");
        });

        app.get("/api/auth/me", verifyUser, async (req, res) => {
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

        app.get("/api/admin/stats", verifyUser, verifyAdmin, async (req, res) => {
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

        app.get("/api/dashboard/stats", verifyUser, async (req, res) => {
            try {
                const role = req.user?.role || "donor";
                const email = req.user?.email;

                if (role === "admin") {
                    const totalDonationRequests =
                        await donationRequestCollection.countDocuments();

                    const totalDonors = await userCollection.countDocuments({
                        role: "donor",
                    });

                    const totalVolunteers = await userCollection.countDocuments({
                        role: "volunteer",
                    });

                    const totalFunding = 0;

                    return res.status(200).json({
                        success: true,
                        role: "admin",
                        stats: {
                            totalDonationRequests,
                            totalDonors,
                            totalVolunteers,
                            totalFunding,
                        },
                    });
                }

                if (role === "volunteer") {
                    const totalPublicRequests =
                        await donationRequestCollection.countDocuments();

                    const pendingRequests =
                        await donationRequestCollection.countDocuments({
                            donationStatus: "pending",
                        });

                    const inProgressRequests =
                        await donationRequestCollection.countDocuments({
                            donationStatus: "inprogress",
                        });

                    const completedRequests =
                        await donationRequestCollection.countDocuments({
                            donationStatus: "done",
                        });

                    return res.status(200).json({
                        success: true,
                        role: "volunteer",
                        stats: {
                            totalPublicRequests,
                            pendingRequests,
                            inProgressRequests,
                            completedRequests,
                        },
                    });
                }

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
        app.get("/api/admin/users", verifyUser, verifyAdmin, async (req, res) => {
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

        // Block or unblock user
        app.patch("/api/admin/users/:id/status", verifyUser, verifyAdmin, async (req, res) => {
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
        app.patch("/api/admin/users/:id/role", verifyUser, verifyAdmin, async (req, res) => {
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

        app.post("/api/donationRequests", async (req, res) => {
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
        app.get("/api/donationRequests/my", async (req, res) => {
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
        app.get("/api/donationRequests/details/:id", async (req, res) => {
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


        // Confirm donation and change status pending to inprogress
        app.patch("/api/donationRequests/:id/donate", async (req, res) => {
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


        // Get single donation request by id
        app.get("/api/donationRequests/:id", async (req, res) => {
            try {
                const { id } = req.params;
                const { email } = req.query;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                if (!email) {
                    return res.status(400).json({
                        success: false,
                        message: "Requester email is required.",
                    });
                }

                const request = await donationRequestCollection.findOne({
                    _id: new ObjectId(id),
                    requesterEmail: email,
                });

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

        // Update own donation request
        app.put("/api/donationRequests/:id", async (req, res) => {
            try {
                const { id } = req.params;
                const body = req.body;

                if (!ObjectId.isValid(id)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid donation request id.",
                    });
                }

                if (!body.requesterEmail) {
                    return res.status(400).json({
                        success: false,
                        message: "Requester email is required.",
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
                        requesterEmail: body.requesterEmail,
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
        app.patch("/api/donationRequests/:id/status", async (req, res) => {
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
        app.delete("/api/donationRequests/:id", async (req, res) => {
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