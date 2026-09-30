import app from "./app.js";
import { config } from "./config.js";

app.listen(config.port, () => {
  console.log(`SecureBlog v2 sur http://localhost:${config.port}`);
});
