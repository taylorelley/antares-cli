const express = require("express");
const app = express();
app.get("/search", (req, res) => {
  const q = req.query.q;
  res.send("<div>" + q + "</div>");
});
