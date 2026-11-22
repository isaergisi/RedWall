// Each line marked "expect: RULE-ID" must produce exactly that finding (needs opengrep or semgrep).
const cp = require('child_process');
const { exec } = require('child_process');
const crypto = require('crypto');
const https = require('https');

function handler(req, res, db, el, file, id, body, x) {
  eval(req.query.code);                                   // expect: RW-JS-CODEI
  eval("1 + 1");
  setTimeout(() => run(), 10);
  setTimeout("run(" + x + ")", 1);                        // expect: RW-JS-CODEI
  new Function("a", body);                                // expect: RW-JS-CODEI
  cp.exec("ls " + req.query.dir);                         // expect: RW-JS-CMDI
  exec(`cat ${file}`);                                    // expect: RW-JS-CMDI
  cp.exec("ls " + x + " -la");                            // expect: RW-JS-CMDI
  cp.exec("ls");
  db.query("SELECT * FROM u WHERE id=" + req.params.id);  // expect: RW-JS-SQLI
  db.query(`SELECT * FROM u WHERE id=${id}`);             // expect: RW-JS-SQLI
  db.query("SELECT * FROM u WHERE id=?", [id]);
  cache.get("x" + id);
  el.innerHTML = req.query.name;                          // expect: RW-JS-XSS
  el.innerHTML = "<b>hi</b>";
  document.write(location.hash);                          // expect: RW-JS-XSS
  https.request({ host: x, rejectUnauthorized: false });  // expect: RW-JS-TLS
  crypto.createHash('md5');                               // expect: RW-JS-WEAKHASH
  crypto.createHash('sha256');
}

module.exports = { handler };
