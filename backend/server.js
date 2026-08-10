const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./db");
const jwt = require("jsonwebtoken");
const authenticateToken = require("./auth");

const app = express();

const PORT = 3000;

app.use(express.json());

app.post("/api/users", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                status: "error",
                message: "Name, email and password are required"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                status: "error",
                message: "Password must be at least 6 characters"
            });
        }

        const [existingUsers] = await db.query(
            "SELECT id FROM users WHERE email = ?",
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                status: "error",
                message: "Email already registered"
            });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const [result] = await db.query(
            `INSERT INTO users (name, email, password_hash)
             VALUES (?, ?, ?)`,
            [name, email, passwordHash]
        );

        res.status(201).json({
            status: "ok",
            message: "User created successfully",
            user: {
                id: result.insertId,
                name,
                email
            }
        });
    } catch (error) {
        console.error("Error creating user:", error);

        res.status(500).json({
            status: "error",
            message: "Could not create user"
        });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                status: "error",
                message: "Email and password are required"
            });
        }

        const [users] = await db.query(
            `SELECT id, name, email, password_hash
             FROM users
             WHERE email = ?`,
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                status: "error",
                message: "Invalid email or password"
            });
        }

        const user = users[0];

        const passwordMatches = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatches) {
            return res.status(401).json({
                status: "error",
                message: "Invalid email or password"
            });
        }

       const token = jwt.sign(
    {
        id: user.id,
        email: user.email
    },
    process.env.JWT_SECRET,
    {
        expiresIn: "2h"
    }
);

res.json({
    status: "ok",
    message: "Login successful",
    user: {
        id: user.id,
        name: user.name,
        email: user.email
    },
    token
});
} catch (error) {
        console.error("Error during login:", error);

        res.status(500).json({
            status: "error",
            message: "Could not login"
        });
    }
});

app.get("/api/health", async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT 1 AS database_connected"
        );

        res.json({
            status: "ok",
            message: "CV Analyzer API is running",
            database: rows[0].database_connected === 1
        });
    } catch (error) {
        console.error("Database connection error:", error);

        res.status(500).json({
            status: "error",
            message: "Database connection failed"
        });
    }
});

app.get("/api/users", async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT id, name, email, created_at, updated_at FROM users"
        );

        res.json({
            status: "ok",
            users: rows
        });
    } catch (error) {
        console.error("Error fetching users:", error);

        res.status(500).json({
            status: "error",
            message: "Could not fetch users"
        });
    }
});

app.post("/api/resumes", authenticateToken, async (req, res) => {
    try {
        const {
            title,
            file_path,
            extracted_text
        } = req.body;

        if (!title) {
            return res.status(400).json({
                status: "error",
                message: "Title is required"
            });
        }

        const [result] = await db.query(
            `INSERT INTO resumes (
                user_id,
                title,
                file_path,
                extracted_text
            )
            VALUES (?, ?, ?, ?)`,
            [
                req.user.id,
                title,
                file_path || null,
                extracted_text || null
            ]
        );

        res.status(201).json({
            status: "ok",
            message: "Resume created successfully",
            resume: {
                id: result.insertId,
                user_id: req.user.id,
                title,
                file_path: file_path || null,
                extracted_text: extracted_text || null
            }
        });
    } catch (error) {
        console.error("Error creating resume:", error);

        res.status(500).json({
            status: "error",
            message: "Could not create resume"
        });
    }
});

app.get("/api/resumes", authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                r.id,
                r.user_id,
                u.name AS user_name,
                r.title,
                r.file_path,
                r.extracted_text,
                r.created_at,
                r.updated_at
            FROM resumes r
            INNER JOIN users u
                ON r.user_id = u.id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
        `, [req.user.id]);

        res.json({
            status: "ok",
            resumes: rows
        });
    } catch (error) {
        console.error("Error fetching resumes:", error);

        res.status(500).json({
            status: "error",
            message: "Could not fetch resumes"
        });
    }
});

app.post("/api/job-offers", authenticateToken, async (req, res) => {
    try {
        const {
            title,
            company,
            description,
            source_url
        } = req.body;

        if (!title || !description) {
            return res.status(400).json({
                status: "error",
                message: "Title and description are required"
            });
        }

        const [result] = await db.query(
            `INSERT INTO job_offers (
                user_id,
                title,
                company,
                description,
                source_url
            )
            VALUES (?, ?, ?, ?, ?)`,
            [
                req.user.id,
                title,
                company || null,
                description,
                source_url || null
            ]
        );

        res.status(201).json({
            status: "ok",
            message: "Job offer created successfully",
            job_offer: {
                id: result.insertId,
                user_id: req.user.id,
                title,
                company: company || null,
                description,
                source_url: source_url || null
            }
        });
    } catch (error) {
        console.error("Error creating job offer:", error);

        res.status(500).json({
            status: "error",
            message: "Could not create job offer"
        });
    }
});

app.get("/api/job-offers", authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                j.id,
                j.user_id,
                u.name AS user_name,
                j.title,
                j.company,
                j.description,
                j.source_url,
                j.created_at,
                j.updated_at
            FROM job_offers j
            INNER JOIN users u
                ON j.user_id = u.id
            WHERE j.user_id = ?
            ORDER BY j.created_at DESC
        `, [req.user.id]);

        res.json({
            status: "ok",
            job_offers: rows
        });
    } catch (error) {
        console.error("Error fetching job offers:", error);

        res.status(500).json({
            status: "error",
            message: "Could not fetch job offers"
        });
    }
});

app.post("/api/analyses", authenticateToken, async (req, res) => {
    try {
        const {
            resume_id,
            job_offer_id,
            match_score,
            summary
        } = req.body;

        if (
            resume_id === undefined ||
            job_offer_id === undefined ||
            match_score === undefined
        ) {
            return res.status(400).json({
                status: "error",
                message: "resume_id, job_offer_id and match_score are required"
            });
        }

        if (match_score < 0 || match_score > 100) {
            return res.status(400).json({
                status: "error",
                message: "match_score must be between 0 and 100"
            });
        }

        const [resumes] = await db.query(
            `SELECT id
             FROM resumes
             WHERE id = ? AND user_id = ?`,
            [resume_id, req.user.id]
        );

        if (resumes.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Resume not found"
            });
        }

        const [jobOffers] = await db.query(
            `SELECT id
             FROM job_offers
             WHERE id = ? AND user_id = ?`,
            [job_offer_id, req.user.id]
        );

        if (jobOffers.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Job offer not found"
            });
        }

        const [result] = await db.query(
            `INSERT INTO analyses (
                resume_id,
                job_offer_id,
                match_score,
                summary
            )
            VALUES (?, ?, ?, ?)`,
            [
                resume_id,
                job_offer_id,
                match_score,
                summary || null
            ]
        );

        res.status(201).json({
            status: "ok",
            message: "Analysis created successfully",
            analysis: {
                id: result.insertId,
                resume_id,
                job_offer_id,
                match_score,
                summary: summary || null
            }
        });
    } catch (error) {
        console.error("Error creating analysis:", error);

        res.status(500).json({
            status: "error",
            message: "Could not create analysis"
        });
    }
});

app.get("/api/analyses", authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                a.id,
                a.resume_id,
                r.title AS resume_title,
                a.job_offer_id,
                j.title AS job_title,
                j.company,
                a.match_score,
                a.summary,
                a.created_at,
                a.updated_at
            FROM analyses a
            INNER JOIN resumes r
                ON a.resume_id = r.id
            INNER JOIN job_offers j
                ON a.job_offer_id = j.id
            WHERE r.user_id = ?
            ORDER BY a.created_at DESC
        `, [req.user.id]);

        res.json({
            status: "ok",
            analyses: rows
        });
    } catch (error) {
        console.error("Error fetching analyses:", error);

        res.status(500).json({
            status: "error",
            message: "Could not fetch analyses"
        });
    }
});

app.get("/api/profile", authenticateToken, async (req, res) => {
    try {
        const [users] = await db.query(
            `SELECT id, name, email, created_at, updated_at
             FROM users
             WHERE id = ?`,
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "User not found"
            });
        }

        res.json({
            status: "ok",
            user: users[0]
        });
    } catch (error) {
        console.error("Error fetching profile:", error);

        res.status(500).json({
            status: "error",
            message: "Could not fetch profile"
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});