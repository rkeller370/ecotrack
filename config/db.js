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
      return;
    } catch (err) {
      console.error(`Failed to connect to MongoDB (attempt ${i + 1}):`, err);
      if (i === retries - 1) throw err;
      await new Promise((res) => setTimeout(res, delay));
    }
  }
};

const getDb = async () => {
  if (!db)
    await initializeMongo();
console.log(db)
  return db;
};

module.exports = { getDb, initializeMongo };
