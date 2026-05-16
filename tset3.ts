// location.search 대신 req.query 사용
function renderUserProfile(req: any, res: any) {
  const username = req.query;        // SOURCE ← 감지됨
  const bio      = req.body;         // SOURCE ← 감지됨
  res.send(username);                // SINK: XSS ← 감지됨
  res.send(bio);                     // SINK: XSS ← 감지됨
}

