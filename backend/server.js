const app = require("./app");
const port = process.env.PORT || 3000;

const db = require("./config/db");

async function startServer() {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

startServer();