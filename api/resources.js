const { MongoClient, ObjectId, GridFSBucket } = require("mongodb");
const crypto = require("crypto");
const { setCorsHeaders } = require("./_cors");

const SESSION_COOKIE = "mrs_session";
const MAX_FILE_SIZE = 3 * 1024 * 1024;
const ALLOWED_FILE_TYPES = new Set([
  "application/pdf",
  "application/msword",
  "application/vnd.ms-excel",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "text/plain",
  "text/csv",
  "image/jpeg",
  "image/png",
  "image/webp"
]);
const FILE_TYPES_BY_EXTENSION = new Map([
  ["pdf", "application/pdf"],
  ["doc", "application/msword"],
  ["docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  ["xls", "application/vnd.ms-excel"],
  ["xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  ["ppt", "application/vnd.ms-powerpoint"],
  ["pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  ["txt", "text/plain"],
  ["csv", "text/csv"],
  ["jpg", "image/jpeg"],
  ["jpeg", "image/jpeg"],
  ["png", "image/png"],
  ["webp", "image/webp"]
]);

let cachedClient = global.portalResourcesMongoClient;

async function getDatabase() {
  if (!process.env.MONGODB_URI) {
    throw new Error("Database configuration is missing.");
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(process.env.MONGODB_URI);
    await cachedClient.connect();
    global.portalResourcesMongoClient = cachedClient;
  }

  return cachedClient.db(
    process.env.PORTAL_DB_NAME || "MRSStaffPortal"
  );
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

function verifySession(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32 || !token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [encoded, signature] = parts;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest();

  let supplied;
  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );
    if (
      typeof payload.uid !== "string" ||
      !/^[a-f\d]{24}$/i.test(payload.uid) ||
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= Date.now()
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function getApprovedUser(req, db) {
  const payload = verifySession(getCookie(req, SESSION_COOKIE));
  if (!payload) return null;

  return db.collection("users").findOne(
    {
      _id: new ObjectId(payload.uid),
      active: true,
      approved: true
    },
    { projection: { name: 1, username: 1, role: 1 } }
  );
}

function isAdmin(user) {
  return String(user.role || "").toUpperCase() === "ADMIN";
}

function getBody(req) {
  return req.body && typeof req.body === "object" ? req.body : {};
}

function validText(value, maximum, required = false) {
  return typeof value === "string" &&
    value.trim().length <= maximum &&
    (!required || value.trim().length > 0);
}

function toResourceDocument(resource) {
  return {
    id: resource._id.toString(),
    kind: resource.kind,
    title: resource.title,
    description: resource.description || "",
    url: resource.url || "",
    fileName: resource.fileName || "",
    contentType: resource.contentType || "",
    fileSize: resource.fileSize || 0,
    createdAt: resource.createdAt
  };
}

function makeSafeDownloadName(fileName) {
  return fileName.replace(/[\r\n"\\]/g, "_");
}

module.exports = async function handler(req, res) {
  const originAllowed = setCorsHeaders(req, res, "GET, POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (!originAllowed) {
    return res.status(403).json({
      ok: false,
      error: "Origin not allowed."
    });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return res.status(405).json({
      ok: false,
      error: "Method not allowed."
    });
  }

  try {
    const db = await getDatabase();
    const user = await getApprovedUser(req, db);
    if (!user) {
      return res.status(401).json({
        ok: false,
        authenticated: false,
        error: "Please sign in with an approved account."
      });
    }

    const resources = db.collection("resources");
    const bucket = new GridFSBucket(db, { bucketName: "resourceFiles" });

    if (req.method === "GET") {
      const downloadId = req.query?.download;
      if (downloadId !== undefined) {
        if (
          typeof downloadId !== "string" ||
          !/^[a-f\d]{24}$/i.test(downloadId)
        ) {
          return res.status(400).json({ ok: false, error: "Invalid file ID." });
        }

        const resource = await resources.findOne({
          _id: new ObjectId(downloadId),
          kind: "file"
        });
        if (!resource || !/^[a-f\d]{24}$/i.test(resource.fileId || "")) {
          return res.status(404).json({ ok: false, error: "File not found." });
        }

        const safeName = makeSafeDownloadName(resource.fileName || "download");
        const fallbackName = safeName.replace(/[^\x20-\x7E]/g, "_");
        res.setHeader("Content-Type", resource.contentType);
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${fallbackName}"; filename*=UTF-8''${encodeURIComponent(safeName)}`
        );
        res.setHeader("Content-Length", resource.fileSize);

        const stream = bucket.openDownloadStream(new ObjectId(resource.fileId));
        stream.on("error", error => {
          console.error("Resource download failed:", error.message);
          if (res.headersSent) {
            res.destroy(error);
          } else {
            res.status(404).json({ ok: false, error: "File not found." });
          }
        });
        stream.pipe(res);
        return;
      }

      const storedResources = await resources.find({})
        .sort({ createdAt: -1, _id: -1 })
        .limit(200)
        .toArray();
      return res.status(200).json({
        ok: true,
        resources: storedResources.map(toResourceDocument)
      });
    }

    if (!isAdmin(user)) {
      return res.status(403).json({
        ok: false,
        error: "Administrator permission is required."
      });
    }

    const body = getBody(req);
    const now = new Date();

    if (body.action === "createLink") {
      if (
        !validText(body.title, 120, true) ||
        !validText(body.description || "", 1000) ||
        typeof body.url !== "string" ||
        body.url.length > 2048
      ) {
        return res.status(400).json({
          ok: false,
          error: "Enter a title (up to 120 characters), an optional description (up to 1000 characters), and a valid link."
        });
      }

      let url;
      try {
        const suppliedUrl = body.url.trim();
        const urlWithProtocol = /^[a-z][a-z\d+.-]*:/i.test(suppliedUrl)
          ? suppliedUrl
          : `https://${suppliedUrl}`;
        url = new URL(urlWithProtocol);
      } catch {
        return res.status(400).json({
          ok: false,
          error: "Enter a valid web address. Addresses without a protocol are treated as https://."
        });
      }

      if (!["http:", "https:"].includes(url.protocol)) {
        return res.status(400).json({
          ok: false,
          error: "Only http and https links are allowed."
        });
      }

      await resources.insertOne({
        kind: "link",
        title: body.title.trim(),
        description: (body.description || "").trim(),
        url: url.toString(),
        createdBy: user._id.toString(),
        createdAt: now
      });

      return res.status(201).json({ ok: true, message: "Resource link added." });
    }

    if (body.action === "uploadFile") {
      const fileName = typeof body.fileName === "string" ? body.fileName.trim() : "";
      const suppliedContentType = typeof body.contentType === "string"
        ? body.contentType.split(";")[0].trim().toLowerCase()
        : "";
      const extension = fileName.includes(".")
        ? fileName.split(".").pop().toLowerCase()
        : "";
      const contentType = ALLOWED_FILE_TYPES.has(suppliedContentType)
        ? suppliedContentType
        : FILE_TYPES_BY_EXTENSION.get(extension) || suppliedContentType;
      const data = typeof body.data === "string" ? body.data : "";
      const description = typeof body.description === "string" ? body.description.trim() : "";

      if (
        !validText(body.title, 120, true) ||
        fileName.length < 1 ||
        fileName.length > 180 ||
        !validText(description, 1000) ||
        !ALLOWED_FILE_TYPES.has(contentType) ||
        data.length > 4 * Math.ceil(MAX_FILE_SIZE / 3) ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Choose a supported file and provide a title. Supported files include PDF, Office documents, text, CSV, and common images."
        });
      }

      const fileBuffer = Buffer.from(data, "base64");
      if (!fileBuffer.length || fileBuffer.length > MAX_FILE_SIZE) {
        return res.status(413).json({
          ok: false,
          error: "Files must be no larger than 3 MB."
        });
      }

      const upload = bucket.openUploadStream(fileName, {
        contentType,
        metadata: {
          title: body.title.trim(),
          uploadedBy: user._id.toString()
        }
      });
      const fileId = upload.id;

      await new Promise((resolve, reject) => {
        upload.once("error", reject);
        upload.once("finish", resolve);
        upload.end(fileBuffer);
      });

      try {
        await resources.insertOne({
          kind: "file",
          title: body.title.trim(),
          description,
          fileId: fileId.toString(),
          fileName,
          contentType,
          fileSize: fileBuffer.length,
          createdBy: user._id.toString(),
          createdAt: now
        });
      } catch (error) {
        try {
          await bucket.delete(fileId);
        } catch (cleanupError) {
          console.error("Failed to remove unlinked resource upload:", cleanupError.message);
        }
        throw error;
      }

      return res.status(201).json({ ok: true, message: "File uploaded." });
    }

    if (body.action === "deleteResource") {
      if (typeof body.resourceId !== "string" || !/^[a-f\d]{24}$/i.test(body.resourceId)) {
        return res.status(400).json({ ok: false, error: "Invalid resource ID." });
      }

      const resourceId = new ObjectId(body.resourceId);
      const resource = await resources.findOne({ _id: resourceId });
      if (!resource) {
        return res.status(404).json({ ok: false, error: "Resource not found." });
      }

      if (resource.kind === "file") {
        if (!/^[a-f\d]{24}$/i.test(resource.fileId || "")) {
          throw new Error("Stored resource file reference is invalid.");
        }
        await bucket.delete(new ObjectId(resource.fileId));
      }
      await resources.deleteOne({ _id: resourceId });

      return res.status(200).json({ ok: true, message: "Resource deleted." });
    }

    return res.status(400).json({ ok: false, error: "Unknown resource action." });
  } catch (error) {
    console.error("Resources API error:", error.message);
    if (res.headersSent) {
      res.destroy(error);
      return;
    }
    return res.status(500).json({
      ok: false,
      error: "Unable to process the resources request."
    });
  }
};
