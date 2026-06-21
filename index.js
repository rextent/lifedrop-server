const express = require("express");
const cors = require("cors");
const dns = require("node:dns");
require("dotenv").config();

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

async function run() {
    try {
        await client.connect();

        const database = client.db("lifedrop_db");

        donationRequestCollection = database.collection("donationRequests");
        userCollection = database.collection("user");

        app.get("/", (req, res) => {
            res.send("LifeDrop backend is running");
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