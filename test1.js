const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id=' + id); // ← 여기 경고 떠야 함
});
