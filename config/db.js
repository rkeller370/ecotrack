const { MongoClient, ServerApiVersion } = require("mongodb");

const mongoClient = new MongoClient(process.env.MONGO_URI, {
  ssl: true,
  tlsAllowInvalidCertificates: false,
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

const initializeMongo = async (retries = 5, delay = 5000) => {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await mongoClient.connect();
      db = await client.db("Development");
      console.log("Connected to MongoDB");
      return; // Successfully connected, exit the function
    } catch (err) {
      console.error(`Failed to connect to MongoDB (attempt ${i + 1}):`, err);
      if (i === retries - 1) {
        console.error('Max retries reached. Throwing error.');
        throw err; // If we've exhausted retries, throw the error
      }
      await new Promise((res) => setTimeout(res, delay)); // Retry after delay
    }
  }
};

// Ensure the DB is initialized before returning it
const getDb = async () => {
  if (!db) {
    console.log("Initializing MongoDB...");
    await initializeMongo(); // Make sure MongoDB is initialized first
  }
  console.log("Returning DB object:", db); // Logging the db object to verify
  return db;
};

module.exports = { getDb, initializeMongo };
