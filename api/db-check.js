
const { MongoClient } = require("mongodb");

let cachedClient = global.mongoClient;

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  }

  const uri = process.env.MONGODB_URI;
  const apparatusDbName =
    process.env.APPARATUS_DB_NAME || "ApparatusCheck";
  const userCollection =
    process.env.USER_COLLECTION || "users";

  if (!uri) {
    return res.status(500).json({
      ok: false,
      error: "MONGODB_URI is not configured"
    });
  }

  try {
    if (!cachedClient) {
      cachedClient = new MongoClient(uri);
      await cachedClient.connect();
      global.mongoClient = cachedClient;
    } else {
      await cachedClient.connect();
    }

    const db = cachedClient.db(apparatusDbName);

    await db.command({ ping: 1 });

    const collectionExists = await db
      .listCollections(
        { name: userCollection },
        { nameOnly: true }
      )
      .hasNext();

    return res.status(200).json({
      ok: true,
      message: "MongoDB connection successful",
      database: apparatusDbName,
      userCollection,
      collectionExists
    });
  } catch (error) {
    console.error("MongoDB connection check failed:", error.message);

    return res.status(500).json({
      ok: false,
      error: "Database connection failed. Check Vercel configuration."
    });
  }
};
